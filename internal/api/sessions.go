package api

import "context"

func (s *Server) ListSessions(ctx context.Context, request ListSessionsRequestObject) (ListSessionsResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeSession(ctx context.Context, request RevokeSessionRequestObject) (RevokeSessionResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeOtherSessions(ctx context.Context, request RevokeOtherSessionsRequestObject) (RevokeOtherSessionsResponseObject, error) {
	panic("unimplemented")
}
