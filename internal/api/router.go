package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"
	"golang.org/x/text/language"
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

func recoverer(next http.Handler) http.Handler {
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

func clientCountryFromHeader(header string) func(http.Handler) http.Handler {
	safeHeader := http.CanonicalHeaderKey(header)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			country := r.Header.Get(safeHeader)
			if country != "XX" && country != "T1" {
				region, err := language.ParseRegion(country)
				if err != nil || region.IsCountry() {
					country = ""
				}
			}
			ctx := context.WithValue(r.Context(), "clientCountry", country)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClientCountry(ctx context.Context) string {
	if v, ok := ctx.Value("clientCountry").(string); ok {
		return v
	}
	return ""
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
	if s.config.Server.IPHeader != "" {
		r.Use(middleware.ClientIPFromHeader(s.config.Server.IPHeader))
	}
	if s.config.Server.GeoHeader != "" {
		r.Use(clientCountryFromHeader(s.config.Server.GeoHeader))
	}

	// Logging
	r.Use(middleware.Logger)

	// Sending
	r.Use(middleware.Compress(5))
	r.Use(recoverer)

	specs, err := GetSpec()
	if err != nil {
		return nil, fmt.Errorf("couldn't parse OpenAPI specifications: %w", err)
	}
	specs.Servers = nil

	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(specs, &nethttpmiddleware.Options{
		ErrorHandlerWithOpts: validationErrorHandler,
		Skipper: func(r *http.Request) bool {
			if r.Method == http.MethodOptions {
				return true
			}
			path := r.URL.Path
			for _, providerCfg := range s.config.Auth.Providers {
				if path == providerCfg.CallbackPath || strings.HasPrefix(path, providerCfg.CallbackPath) {
					return true
				}
			}
			return false
		},
	})

	strictHandler := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: handleServerError,
	})

	for providerID := range s.config.Auth.Providers {
		log.Printf("registering %v with %v path", providerID, s.config.Auth.Providers[providerID].CallbackPath)
		handler := s.newOAuthCallbackHandler(providerID)
		r.Get(s.config.Auth.Providers[providerID].CallbackPath, handler)
	}

	return validator(HandlerFromMux(strictHandler, r)), nil
}
