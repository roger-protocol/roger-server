package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ServerError{
					Error: struct {
						Code    ServerErrorErrorCode `json:"code"`
						Message string               `json:"message"`
						Type    ServerErrorErrorType `json:"type"`
					}{
						Type:    "ServerError",
						Code:    "internal_server_error",
						Message: "An unexpected internal server error occured",
					},
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func NewRouter(s *Server) http.Handler {
	r := chi.NewRouter()

	// Filtering
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           1200,
	}))
	r.Use(middleware.AllowContentEncoding("identity"))

	// Tracing
	r.Use(middleware.RequestID)
	r.Use(middleware.ClientIPFromHeader("CF-Connecting-IP"))

	// Logging
	r.Use(middleware.Logger)

	// Sending
	r.Use(middleware.Compress(5))
	r.Use(Recoverer)

	strictHandler := NewStrictHandler(s, nil)
	HandlerFromMux(strictHandler, r)

	return r
}
