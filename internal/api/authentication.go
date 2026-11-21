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
	"github.com/roger-protocol/roger-server/internal/db"
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
		return InitiateOAuthLogin400JSONResponse(newApiError("unsupported_response_type", "Unsupported response type. Expected 'code'")), nil
	}

	url, err := s.providers.GetProviderRedirectURL(
		params.Provider,
		params.CodeChallenge,
		string(params.CodeChallengeMethod),
		params.State,
		params.RedirectUri,
	)
	if err != nil {
		var code string
		switch {
		case errors.Is(err, services.ErrUnsupportedProvider):
			code = "unsupported_provider"
		case errors.Is(err, services.ErrIllegalRedirectUri):
			code = "invalid_redirect_uri"
		case errors.Is(err, services.ErrUnknownCodeChallengeMethod):
			code = "invalid_request"
		default:
			return nil, err
		}

		return InitiateOAuthLogin400JSONResponse(newApiError(code, err.Error())), nil
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
			writeError(w, http.StatusBadRequest, "invalid_request", "missing state")
			return
		}
		oauthState, err := s.providers.DecodeState(state)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid state")
			return
		}

		// Parse the redirect URL
		redirectURL, err := url.Parse(oauthState.RedirectURI)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid redirect URI in state")
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

		ac, err := s.oauth.HandleOAuthCallback(ctx, s.queries, providerID, oauthState, code)
		if err != nil {
			log.Printf("error while handling oauth callback: %v", err)
			redirectWithError("server_error", "there was an error while handling your request, please try again later.")
			return
		}

		// Redirect to the callback url with the code and client state
		q := redirectURL.Query()
		q.Set("code", ac)
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
			return ExchangeToken400JSONResponse(newApiError("invalid_request", "invalid request body")), nil
		}
		var clientName string
		if body.ClientName != nil {
			clientName = *body.ClientName
		}

		user, err := s.oauth.ConsumeAuthorizationCode(ctx, s.queries, *authorizationCode, *redirectUri, *codeVerifier)
		if err != nil {
			if errors.Is(err, services.ErrInvalidGrant) {
				return ExchangeToken400JSONResponse(newApiError("invalid_grant", err.Error())), nil
			}
			return nil, fmt.Errorf("consume authorization code: %w", err)
		}

		ipAddress := middleware.GetClientIP(ctx)
		country := GetClientCountry(ctx)

		createdSession, err := s.sessions.CreateSession(ctx, s.queries, user, ipAddress, country, clientName)
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
			return ExchangeToken400JSONResponse(newApiError("invalid_request", "invalid request body")), nil
		}
		ipAddress := middleware.GetClientIP(ctx)
		country := GetClientCountry(ctx)

		newSession, err := s.sessions.RefreshSession(ctx, s.queries, *refreshToken, ipAddress, country)
		if err != nil {
			if errors.Is(err, services.ErrInvalidGrant) {
				return ExchangeToken400JSONResponse(newApiError("invalid_grant", err.Error())), nil
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

	return ExchangeToken400JSONResponse(newApiError("unsupported_grant_type", "The given grant type is invalid")), nil
}

func (s *Server) RevokeToken(ctx context.Context, request RevokeTokenRequestObject) (RevokeTokenResponseObject, error) {
	body := request.Body

	if strings.Count(body.Token, ".") == 2 && strings.HasPrefix(body.Token, "eyJ") {
		accessToken := body.Token
		claims, err := s.tokens.ParseJwt(accessToken, jwt.WithoutClaimsValidation())
		if err != nil {
			fmt.Printf("err: %v\n", err)
			if errors.Is(err, services.ErrInvalidJwt) {
				return RevokeToken200Response{}, nil
			}
			return nil, err
		}

		session, err := s.queries.RevokeSession(ctx, db.RevokeSessionParams{ID: claims.SessionId, UserID: claims.Subject})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return RevokeToken200Response{}, nil
			}
			return nil, err
		}
		s.tokens.RevokeJwt(ctx, session.AccessTokenJti)
		return RevokeToken200Response{}, nil
	}

	if strings.HasPrefix(body.Token, "rgr_rt_") {
		refreshToken := body.Token
		rtHash := crypto.Hash256([]byte(refreshToken), hex.EncodeToString)

		session, err := s.queries.RevokeSessionFromRefreshToken(ctx, rtHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		s.tokens.RevokeJwt(ctx, session.AccessTokenJti)
		return RevokeToken200Response{}, nil
	}

	return RevokeToken400JSONResponse(newApiError("unsupported_grant_type", "Unsupported grant type")), nil
}
