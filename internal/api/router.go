package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"
)

func handleServerError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("internal error: %v", err)
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

func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				handleServerError(w, r, nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func validationErrorHandler(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
	var errorCode ValidationErrorErrorCode
	var errorMessage string

	if routeErr, ok := errors.AsType[*routers.RouteError](err); ok {
		errorCode = "not_found"
		errorMessage = routeErr.Error()
	} else if reqErr, ok := errors.AsType[*openapi3filter.RequestError](err); ok {
		if reqErr.RequestBody != nil {
			errorCode = "invalid_body"
		} else if reqErr.Parameter != nil {
			if reqErr.Parameter.In == "query" {
				errorCode = "invalid_query"
			} else {
				errorCode = "invalid_params"
			}
		}
		errorMessage = reqErr.Error()
	}

	resp := ValidationError{
		Error: struct {
			Code    ValidationErrorErrorCode "json:\"code\""
			Message string                   "json:\"message\""
			Type    ValidationErrorErrorType "json:\"type\""
		}{
			Type:    "ValidationError",
			Code:    errorCode,
			Message: errorMessage,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(opts.StatusCode)
	json.NewEncoder(w).Encode(resp)
}

func NewRouter(s *Server) (http.Handler, error) {
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

	specs, err := GetSpec()
	if err != nil {
		return nil, fmt.Errorf("couldn't parse OpenAPI specifications: %w", err)
	}
	specs.Servers = nil

	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(specs, &nethttpmiddleware.Options{
		ErrorHandlerWithOpts: validationErrorHandler,
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: handleServerError,
	})
	return validator(HandlerFromMux(strictHandler, r)), nil
}
