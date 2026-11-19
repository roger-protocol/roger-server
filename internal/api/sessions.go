package api

import (
	"context"
	"time"

	"github.com/roger-protocol/roger-server/internal/convert"
)

func (s *Server) ListSessions(ctx context.Context, request ListSessionsRequestObject) (ListSessionsResponseObject, error) {
	actor, ok := GetActorFromContext(ctx)
	if !ok || actor.SessionID == nil {
		return ListSessions500JSONResponse(serverError), nil
	}

	dbSessions, err := s.queries.GetUserSessions(ctx, actor.UserID)
	if err != nil {
		return ListSessions500JSONResponse(newApiError("server_error", "couldn't reach database")), nil
	}

	var sessions []UserSession
	for _, session := range dbSessions {
		createdAt, err := time.Parse(time.RFC3339Nano, session.CreatedAt)
		if err != nil {
			return ListSessions500JSONResponse(serverError), nil
		}
		lastUsedAt, err := time.Parse(time.RFC3339Nano, session.LastUsedAt)
		if err != nil {
			return ListSessions500JSONResponse(serverError), nil
		}

		sessions = append(sessions, UserSession{
			Id:         session.ID,
			ClientName: session.ClientName.String,
			Country:    convert.FromNullString(session.Country),
			IpAddress:  session.IpAddress.String,
			IsCurrent:  session.ID == *actor.SessionID,
			CreatedAt:  createdAt,
			LastUsedAt: lastUsedAt,
		})
	}
	return ListSessions200JSONResponse(sessions), nil
}

func (s *Server) RevokeSession(ctx context.Context, request RevokeSessionRequestObject) (RevokeSessionResponseObject, error) {
	panic("unimplemented")
}

func (s *Server) RevokeOtherSessions(ctx context.Context, request RevokeOtherSessionsRequestObject) (RevokeOtherSessionsResponseObject, error) {
	panic("unimplemented")
}
