package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

type WorkspaceService struct {
	db *sql.DB
}

func NewWorkspaceService(db *sql.DB) *WorkspaceService {
	return &WorkspaceService{db: db}
}

func (s *WorkspaceService) CreatePersonalWorkspaceTx(ctx context.Context, q *db.Queries, user db.User) (db.Workspace, error) {
	// Create Workspace
	now := time.Now().UTC().Format(time.RFC3339)
	workspace, err := q.CreateWorkspace(ctx, db.CreateWorkspaceParams{
		ID:         crypto.GenerateID("rgr_wsp"),
		Name:       user.Username + "'s Workspace",
		IsPersonal: true,
		CreatedBy:  user.ID,
		CreatedAt:  now,
	})
	if err != nil {
		return db.Workspace{}, fmt.Errorf("create workspace: %w", err)
	}

	// Add user to his workspace
	_, err = q.CreateWorkspaceMember(ctx, db.CreateWorkspaceMemberParams{
		WorkspaceID: workspace.ID,
		UserID:      user.ID,
		Role:        "owner",
		JoinedAt:    now,
	})
	if err != nil {
		return db.Workspace{}, fmt.Errorf("create workspace member: %w", err)
	}

	return workspace, nil
}
