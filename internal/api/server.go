package api

import (
	"database/sql"
	"log/slog"

	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	"github.com/roger-protocol/roger-server/internal/services"
)

type Server struct {
	db         *sql.DB
	queries    *db.Queries
	config     *config.Config
	logger     *slog.Logger
	users      *services.UserService
	tokens     *services.TokenService
	providers  *services.ProviderService
	sessions   *services.SessionService
	oauth      *services.OAuthService
	workspaces *services.WorkspaceService
}

var _ StrictServerInterface = (*Server)(nil)

func NewServer(db *sql.DB, q *db.Queries, cfg *config.Config, logger *slog.Logger) *Server {
	workspaces := services.NewWorkspaceService(db)
	users := services.NewUserService(db, workspaces)
	tokens := services.NewTokenService(logger, cfg)
	providers := services.NewProviderService(cfg)
	sessions := services.NewSessionService(tokens)
	oauth := services.NewOAuthService(logger, db, providers, users)

	return &Server{
		db:         db,
		queries:    q,
		config:     cfg,
		logger:     logger,
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
