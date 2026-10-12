package api

import "context"

func (s *Server) InitiateOAuthLogin(ctx context.Context, request InitiateOAuthLoginRequestObject) (InitiateOAuthLoginResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) ExchangeToken(ctx context.Context, request ExchangeTokenRequestObject) (ExchangeTokenResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeToken(ctx context.Context, request RevokeTokenRequestObject) (RevokeTokenResponseObject, error) {
	panic("unimplemented")
}
