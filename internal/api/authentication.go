package api

import (
	"context"
	"errors"
	"net/http"

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
		} else {
			return nil, err
		}
	}

	return InitiateOAuthLogin302ResponseWithLocation{
		Location: url,
	}, nil
}

func (s *Server) ExchangeToken(ctx context.Context, request ExchangeTokenRequestObject) (ExchangeTokenResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeToken(ctx context.Context, request RevokeTokenRequestObject) (RevokeTokenResponseObject, error) {
	panic("unimplemented")
}
