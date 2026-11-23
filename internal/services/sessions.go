package services

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/roger-protocol/roger-server/internal/convert"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

type SessionService struct {
	tokens *TokenService
}

func NewSessionService(tokens *TokenService) *SessionService {
	return &SessionService{tokens: tokens}
}

type CreatedSession struct {
	Session      db.Session
	AccessToken  string
	RefreshToken string
	Claims       JWTClaims
}

func (s *SessionService) CreateSession(ctx context.Context, q *db.Queries, user db.User, ipAddress string, country string, clientName string) (CreatedSession, error) {
	// Create a JWT for the session
	sessId := crypto.GenerateID("rgr_sess")
	jwt, claims, err := s.tokens.CreateJWT(user, sessId)
	if err != nil {
		return CreatedSession{}, fmt.Errorf("create jwt: %w", err)
	}

	// Create the session
	refreshToken, err := crypto.GenerateSafeToken("rgr_rt")
	if err != nil {
		return CreatedSession{}, fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	session, err := q.CreateSession(ctx, db.CreateSessionParams{
		ID:                   sessId,
		UserID:               user.ID,
		IpAddress:            convert.ToNullString(ipAddress),
		Country:              convert.ToNullString(country),
		ClientName:           convert.ToNullString(clientName),
		RefreshTokenHash:     crypto.Hash256([]byte(refreshToken), hex.EncodeToString),
		AccessTokenJti:       claims.ID,
		AccessTokenExpiresAt: claims.ExpiresAt.Format(time.RFC3339),
		CreatedAt:            now,
		LastUsedAt:           now,
	})
	if err != nil {
		return CreatedSession{}, fmt.Errorf("database error: %w", err)
	}

	// Create the token response
	tokenResponse := CreatedSession{
		Session:      session,
		AccessToken:  jwt,
		RefreshToken: refreshToken,
		Claims:       claims,
	}

	return tokenResponse, nil
}
func (s *SessionService) GetSessionFromRefreshToken(ctx context.Context, q *db.Queries, refreshToken string) (db.Session, error) {
	rtHash := crypto.Hash256([]byte(refreshToken), hex.EncodeToString)
	session, err := q.GetSessionFromRefreshToken(ctx, rtHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.Session{}, ErrInvalidRefreshToken
		}
		return db.Session{}, fmt.Errorf("database error: %w", err)
	}
	return session, nil
}

// Possible errors:
// - ErrInvalidRefreshToken
func (s *SessionService) RefreshSession(ctx context.Context, q *db.Queries, refreshToken string, ipAddress string, country string) (CreatedSession, error) {
	oldSession, err := s.GetSessionFromRefreshToken(ctx, q, refreshToken)
	if err != nil {
		return CreatedSession{}, err
	}

	user, err := q.GetUserByID(ctx, oldSession.UserID)
	if err != nil {
		return CreatedSession{}, fmt.Errorf("fetch user profile: %w", err)
	}

	jwt, claims, err := s.tokens.CreateJWT(user, oldSession.ID)
	if err != nil {
		return CreatedSession{}, fmt.Errorf("create jwt: %w", err)
	}

	if ipAddress == "" {
		ipAddress = oldSession.IpAddress.String
		country = oldSession.Country.String
	} else if country == "" {
		country = oldSession.Country.String
	}

	newSession, err := q.RefreshSession(ctx, db.RefreshSessionParams{
		ID:                   oldSession.ID,
		IpAddress:            convert.ToNullString(ipAddress),
		Country:              convert.ToNullString(country),
		AccessTokenJti:       claims.ID,
		AccessTokenExpiresAt: claims.ExpiresAt.Format(time.RFC3339),
		LastUsedAt:           time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return CreatedSession{}, fmt.Errorf("database error: %w", err)
	}
	s.tokens.RevokeJwt(ctx, oldSession.AccessTokenJti)

	return CreatedSession{
		Session:      newSession,
		AccessToken:  jwt,
		RefreshToken: refreshToken,
		Claims:       claims,
	}, nil
}
