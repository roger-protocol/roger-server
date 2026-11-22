package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/roger-protocol/roger-server/internal/convert"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

type UserService struct {
	workspaces *WorkspaceService
	db         *sql.DB
}

func NewUserService(db *sql.DB, workspaces *WorkspaceService) *UserService {
	return &UserService{db: db, workspaces: workspaces}
}

func (s *UserService) CreateUserTx(ctx context.Context, q *db.Queries, username string, email string, email_verified bool) (db.User, error) {
	id := crypto.GenerateID("rgr_usr")
	if username == "" {
		if email == "" {
			username = id
		} else {
			username = email
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	newUser, err := q.CreateUser(ctx, db.CreateUserParams{
		ID:            id,
		Username:      username,
		Email:         convert.ToNullString(email),
		EmailVerified: convert.BoolToNullInt64(email_verified, email != ""),
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	if err != nil {
		return db.User{}, fmt.Errorf("create user: %w", err)
	}

	_, err = s.workspaces.CreatePersonalWorkspaceTx(ctx, q, newUser)
	if err != nil {
		return db.User{}, fmt.Errorf("create personal workspace: %w", err)
	}

	return newUser, nil
}
func (s *UserService) GetOrCreateUserFromProviderClaimsTx(ctx context.Context, q *db.Queries, providerID string, claims providerClaims) (db.User, bool, error) {
	provider, err := q.GetProviderFromSubject(ctx, db.GetProviderFromSubjectParams{ProviderID: providerID, Subject: claims.Subject})
	if err == nil {
		user, err := q.GetUserByID(ctx, provider.UserID)
		if err != nil {
			return db.User{}, false, fmt.Errorf("retrieve user: %w", err)
		}
		return user, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.User{}, false, fmt.Errorf("database error: %w", err)
	}

	user, err := s.CreateUserTx(ctx, q, claims.Username, claims.Email, claims.EmailVerified)
	if err != nil {
		return db.User{}, false, fmt.Errorf("create user: %w", err)
	}
	return user, true, nil
}
