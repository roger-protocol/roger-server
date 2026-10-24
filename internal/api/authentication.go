package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/roger-protocol/roger-server/internal/services"
)

type InitiateOAuthLogin302ResponseWithLocation struct {
	Location string
}

func (r InitiateOAuthLogin302ResponseWithLocation) VisitInitiateOAuthLoginResponse(w http.ResponseWriter) error {
	w.Header().Set("Location", r.Location)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (s *Server) InitiateOAuthLogin(ctx context.Context, request InitiateOAuthLoginRequestObject) (InitiateOAuthLoginResponseObject, error) {
	params := request.Params
	url, err := s.auth.GetProviderRedirectURL(
		params.Provider,
		params.CodeChallenge,
		string(*params.CodeChallengeMethod),
		params.State,
		params.RedirectUri,
	)
	if err != nil {
		if errors.Is(err, services.ErrUnsupportedProvider) {
			return InitiateOAuthLogin400JSONResponse{Error: err.Error()}, nil
		} else if errors.Is(err, services.ErrIllegalRedirectUri) {
			return InitiateOAuthLogin400JSONResponse{Error: err.Error()}, nil
		} else {
			return nil, err
		}
	}

	return InitiateOAuthLogin302ResponseWithLocation{
		Location: url,
	}, nil
}

func (s *Server) newOAuthCallbackHandler(providerID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract query informations
		ctx := r.Context()
		query := r.URL.Query()

		code := query.Get("code")
		state := query.Get("state")
		oauthErr := query.Get("error")
		oauthErrDesc := query.Get("error_description")

		// Decode the encrypted state passed to the provider by the server
		if state == "" {
			http.Error(w, "missing state", http.StatusBadRequest)
			return
		}
		oauthState, err := s.auth.DecodeState(state)
		if err != nil {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}

		// Parse the redirect URL
		redirectURL, err := url.Parse(oauthState.RedirectURI)
		if err != nil {
			http.Error(w, "invalid redirect URI in state", http.StatusBadRequest)
			return
		}

		redirectWithError := func(errCode string, errDescription string) {
			q := redirectURL.Query()
			q.Set("error", errCode)
			q.Set("state", oauthState.ClientState)
			if errDescription != "" {
				q.Set("error_description", errDescription)
			}
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
		}
		if oauthErr != "" {
			redirectWithError(oauthErr, oauthErrDesc)
			return
		}
		if code == "" {
			redirectWithError("server_error", "missing authorization code from provider")
			return
		}

		// Exchange the provider code for a roger user
		user, err := s.auth.GetUserFromProviderCode(ctx, providerID, code)
		if err != nil {
			log.Printf("oauth exchange error for provider %s: %v", providerID, err)
			redirectWithError("server_error", "failed to authenticate with provider")
			return
		}
		log.Printf("successfully authenticated user: %s (%s)", user.ID, user.Username)

		// Create a transaction
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			log.Printf("transaction creation failed: %v", err)
			redirectWithError("server_error", "failed to create database transaction")
			return
		}
		defer tx.Rollback()
		qtx := s.queries.WithTx(tx)

		// Clean previous user authorization codes
		_, err = qtx.DeleteUserAuthorizationCodes(ctx, user.ID)
		if err != nil {
			log.Printf("authorization codes deletion failed: %v", err)
			redirectWithError("server_error", "failed to clean authorization codes")
			return
		}
		// Create a new authorization code
		id, _, err := s.auth.CreateAuthorizationCode(ctx, qtx, user.ID, oauthState.CodeChallenge, oauthState.CodeChallengeMethod, oauthState.RedirectURI)
		if err != nil {
			log.Printf("authorization code creation failed: %v", err)
			redirectWithError("server_error", "failed to create authorization code")
			return
		}

		// Commit the transaction
		if err = tx.Commit(); err != nil {
			log.Printf("failed to commit transaction: %v", err)
			redirectWithError("server_error", "failed to commit transaction")
			return
		}

		// Redirect to the callback url with the code and client state
		q := redirectURL.Query()
		q.Set("code", id)
		q.Set("state", oauthState.ClientState)
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}

func (s *Server) ExchangeToken(ctx context.Context, request ExchangeTokenRequestObject) (ExchangeTokenResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeToken(ctx context.Context, request RevokeTokenRequestObject) (RevokeTokenResponseObject, error) {
	panic("unimplemented")
}
