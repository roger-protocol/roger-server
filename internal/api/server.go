package api

import (
	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	"github.com/roger-protocol/roger-server/internal/services"
)

type Server struct {
	queries *db.Queries
	config  *config.Config
	auth    *services.AuthService
}

var _ StrictServerInterface = (*Server)(nil)

func NewServer(q *db.Queries, cfg *config.Config) *Server {
	return &Server{
		queries: q,
		config:  cfg,
		auth:    services.NewAuthService(q, cfg),
	}
}
