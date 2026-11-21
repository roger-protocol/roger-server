package api

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/roger-protocol/roger-server/internal/convert"
	"github.com/roger-protocol/roger-server/internal/db"
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
	actor, ok := GetActorFromContext(ctx)
	if !ok || actor.SessionID == nil {
		return RevokeSession500JSONResponse(serverError), nil
	}

	session, err := s.queries.RevokeSession(ctx, db.RevokeSessionParams{ID: request.SessionId, UserID: actor.UserID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RevokeSession404JSONResponse(newApiError("resource_not_found", "session not found")), nil
		}
		return RevokeSession500JSONResponse(newApiError("server_error", "couldn't reach database")), nil
	}
	s.tokens.RevokeJwt(ctx, session.AccessTokenJti)

	return RevokeSession204Response{}, nil
}

func (s *Server) RevokeOtherSessions(ctx context.Context, request RevokeOtherSessionsRequestObject) (RevokeOtherSessionsResponseObject, error) {
	actor, ok := GetActorFromContext(ctx)
	if !ok || actor.SessionID == nil {
		return RevokeOtherSessions500JSONResponse(serverError), nil
	}

	sessions, err := s.queries.RevokeAllSessionsExcept(ctx, db.RevokeAllSessionsExceptParams{ID: *actor.SessionID, UserID: actor.UserID})
	if err != nil {
		return RevokeOtherSessions500JSONResponse(newApiError("server_error", "couldn't reach database")), nil
	}
	for _, session := range sessions {
		s.tokens.RevokeJwt(ctx, session.AccessTokenJti)
	}

	return RevokeOtherSessions204Response{}, nil
}
