package api

import (
	"database/sql"

	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	"github.com/roger-protocol/roger-server/internal/services"
)

type Server struct {
	db      *sql.DB
	queries *db.Queries
	config  *config.Config
	auth    *services.AuthService
}

var _ StrictServerInterface = (*Server)(nil)

func NewServer(db *sql.DB, q *db.Queries, cfg *config.Config) *Server {
	return &Server{
		db:      db,
		queries: q,
		config:  cfg,
		auth:    services.NewAuthService(db, q, cfg),
	}
}
