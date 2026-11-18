package api

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roger-protocol/roger-server/internal/crypto"
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

	if params.ResponseType != "code" {
		description := "Unsupported response type. Expected 'code'"
		return InitiateOAuthLogin400JSONResponse{Error: "unsupported_response_type", ErrorDescription: &description}, nil
	}

	url, err := s.auth.GetProviderRedirectURL(
		params.Provider,
		params.CodeChallenge,
		string(params.CodeChallengeMethod),
		params.State,
		params.RedirectUri,
	)
	if err != nil {
		message := err.Error()
		if errors.Is(err, services.ErrUnsupportedProvider) {
			return InitiateOAuthLogin400JSONResponse{Error: "unsupported_provider", ErrorDescription: &message}, nil
		} else if errors.Is(err, services.ErrIllegalRedirectUri) {
			return InitiateOAuthLogin400JSONResponse{Error: "invalid_redirect_uri", ErrorDescription: &message}, nil
		} else if errors.Is(err, services.ErrUnknownCodeChallengeMethod) {
			return InitiateOAuthLogin400JSONResponse{Error: "invalid_request", ErrorDescription: &message}, nil
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
			if oauthState.ClientState != nil {
				q.Set("state", *oauthState.ClientState)
			}
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
		if oauthState.ClientState != nil {
			q.Set("state", *oauthState.ClientState)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}

func (s *Server) ExchangeToken(ctx context.Context, request ExchangeTokenRequestObject) (ExchangeTokenResponseObject, error) {
	body := request.Body

	if body.GrantType == "authorization_code" {
		authorizationCode := body.Code
		codeVerifier := body.CodeVerifier
		redirectUri := body.RedirectUri
		if authorizationCode == nil || codeVerifier == nil || redirectUri == nil {
			description := "invalid request body"
			return ExchangeToken400JSONResponse{Error: "invalid_request", ErrorDescription: &description}, nil
		}
		var clientName string
		if body.ClientName != nil {
			clientName = *body.ClientName
		}

		user, err := s.auth.ConsumeAuthorizationCode(ctx, s.queries, *authorizationCode, *redirectUri, *codeVerifier)
		if err != nil {
			if errors.Is(err, services.ErrInvalidGrant) {
				message := err.Error()
				return ExchangeToken400JSONResponse{Error: "invalid_grant", ErrorDescription: &message}, nil
			}
			return nil, fmt.Errorf("consume authorization code: %w", err)
		}

		ipAddress := middleware.GetClientIP(ctx)
		country := GetClientCountry(ctx)

		createdSession, err := s.auth.CreateSession(ctx, s.queries, user, ipAddress, country, clientName)
		if err != nil {
			return nil, err
		}

		return ExchangeToken200JSONResponse{
			AccessToken:  createdSession.AccessToken,
			ExpiresIn:    int(services.JwtTTL.Seconds()),
			RefreshToken: createdSession.RefreshToken,
			TokenType:    "Bearer",
		}, nil
	}

	if body.GrantType == "refresh_token" {
		refreshToken := body.RefreshToken
		if refreshToken == nil {
			description := "invalid request body"
			return ExchangeToken400JSONResponse{Error: "invalid_request", ErrorDescription: &description}, nil
		}
		ipAddress := middleware.GetClientIP(ctx)
		country := GetClientCountry(ctx)

		newSession, err := s.auth.RefreshSession(ctx, s.queries, *refreshToken, ipAddress, country)
		if err != nil {
			if errors.Is(err, services.ErrInvalidGrant) {
				message := err.Error()
				return ExchangeToken400JSONResponse{Error: "invalid_grant", ErrorDescription: &message}, nil
			}
			return nil, fmt.Errorf("refresh session: %w", err)
		}

		return ExchangeToken200JSONResponse{
			AccessToken:  newSession.AccessToken,
			ExpiresIn:    int(services.JwtTTL.Seconds()),
			RefreshToken: newSession.RefreshToken,
			TokenType:    "Bearer",
		}, nil
	}

	message := "The given grant type is invalid"
	return ExchangeToken400JSONResponse{Error: "unsupported_grant_type", ErrorDescription: &message}, nil
}

func (s *Server) RevokeToken(ctx context.Context, request RevokeTokenRequestObject) (RevokeTokenResponseObject, error) {
	body := request.Body

	if strings.Count(body.Token, ".") == 2 && strings.HasPrefix(body.Token, "eyJ") {
		accessToken := body.Token
		claims, err := s.auth.ParseJwt(accessToken, jwt.WithoutClaimsValidation())
		if err != nil {
			fmt.Printf("err: %v\n", err)
			if errors.Is(err, services.ErrInvalidJwt) {
				return RevokeToken200Response{}, nil
			}
			return nil, err
		}

		session, err := s.queries.RevokeSession(ctx, claims.SessionId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return RevokeToken200Response{}, nil
			}
			return nil, err
		}
		s.auth.RevokeJwt(ctx, session.AccessTokenJti)
		return RevokeToken200Response{}, nil
	}

	if strings.HasPrefix(body.Token, "rgr_rt_") {
		refreshToken := body.Token
		rtHash := crypto.Hash256([]byte(refreshToken), hex.EncodeToString)

		session, err := s.queries.RevokeSessionFromRefreshToken(ctx, rtHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		s.auth.RevokeJwt(ctx, session.AccessTokenJti)
		return RevokeToken200Response{}, nil
	}

	description := "Unsupported grant type"
	return RevokeToken400JSONResponse{Error: "unsupported_grant_type", ErrorDescription: &description}, nil
}
