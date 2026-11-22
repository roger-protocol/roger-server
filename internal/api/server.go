package api

import (
	"database/sql"

	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	"github.com/roger-protocol/roger-server/internal/services"
)

type Server struct {
	db         *sql.DB
	queries    *db.Queries
	config     *config.Config
	users      *services.UserService
	tokens     *services.TokenService
	providers  *services.ProviderService
	sessions   *services.SessionService
	oauth      *services.OAuthService
	workspaces *services.WorkspaceService
}

var _ StrictServerInterface = (*Server)(nil)

func NewServer(db *sql.DB, q *db.Queries, cfg *config.Config) *Server {
	workspaces := services.NewWorkspaceService(db)
	users := services.NewUserService(db, workspaces)
	tokens := services.NewTokenService(cfg)
	providers := services.NewProviderService(cfg)
	sessions := services.NewSessionService(tokens)
	oauth := services.NewOAuthService(db, providers, users)

	return &Server{
		db:         db,
		queries:    q,
		config:     cfg,
		users:      users,
		tokens:     tokens,
		providers:  providers,
		sessions:   sessions,
		oauth:      oauth,
		workspaces: workspaces,
	}
}

func (s *Server) Close() {
	s.tokens.Close()
}
