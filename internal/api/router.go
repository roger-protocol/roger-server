package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"
	"github.com/roger-protocol/roger-server/internal/logging"
	"github.com/roger-protocol/roger-server/internal/services"
	"golang.org/x/text/language"
)

type AuthError struct {
	Code             string
	ErrorDescription string
}

func (e *AuthError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorDescription
	}
	return e.Code
}

type actorContextKey struct{}

type AuthMethod string

const AuthMethodBearer AuthMethod = "bearer"

type Actor struct {
	UserID     string
	SessionID  *string
	JwtID      string
	AuthMethod AuthMethod
}

func recoverer(next http.Handler) http.Handler {
	workDir, _ := os.Getwd()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					panic(err)
				}

				// Print a clean trace
				pcs := make([]uintptr, 32)               // allocate 32 PCs for up to 32 traces
				n := runtime.Callers(4, pcs)             // Fill the slice with the 32 latest PC traces
				frames := runtime.CallersFrames(pcs[:n]) // Retrieve info about each PC into a "frame"

				var trace strings.Builder
				fmt.Fprintf(&trace, "PanicError: %v\n", err)

				for {
					// Iterate over each frame
					frame, more := frames.Next()

					// Filter frames that are from libraries
					if strings.HasPrefix(frame.Function, "github.com/roger-protocol/roger-server") {
						// Get the relative path of the file path
						relPath, err := filepath.Rel(workDir, frame.File)
						if err != nil || strings.HasPrefix(relPath, "..") {
							relPath = frame.File
						}

						fmt.Fprintf(&trace, "    at %s (%s:%d)\n", frame.Function, relPath, frame.Line)
					}

					if !more {
						break
					}
				}

				log.Print(trace.String())
				writeServerError(w)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func validationErrorHandler(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
	errorMessage := "Invalid request"

	if _, ok := errors.AsType[*routers.RouteError](err); ok {
		errorMessage = "Invalid URL"
	} else if reqErr, ok := errors.AsType[*openapi3filter.RequestError](err); ok {
		switch {
		case reqErr.RequestBody != nil:
			errorMessage = "Invalid request body"
		case reqErr.Parameter != nil:
			switch reqErr.Parameter.In {
			case "query":
				errorMessage = "Invalid request query"
			case "path":
				errorMessage = "Invalid URL params"
			default:
				errorMessage = "Invalid request parameters"
			}
		}
	} else if secErr, ok := errors.AsType[*openapi3filter.SecurityRequirementsError](err); ok {
		var authErr *AuthError
		for _, err := range secErr.Errors {
			if errors.As(err, &authErr) {
				break
			}
		}

		if authErr != nil {
			writeError(w, http.StatusUnauthorized, authErr.Code, authErr.ErrorDescription)
			return
		}

		writeServerError(w)
		return
	}

	writeError(w, opts.StatusCode, "invalid_request", errorMessage)
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

func makeAuthenticationFunc(tokens *services.TokenService) openapi3filter.AuthenticationFunc {
	return func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
		switch ai.SecuritySchemeName {
		case "bearerAuth":
			authHeader := ai.RequestValidationInput.Request.Header.Get("Authorization")
			if authHeader == "" {
				return &AuthError{Code: "invalid_token", ErrorDescription: "missing Authorization header"}
			}

			prefix := "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				return &AuthError{Code: "invalid_token", ErrorDescription: "Authorization header must be Bearer"}
			}
			jwt := strings.TrimPrefix(authHeader, prefix)

			claims, err := tokens.ValidateJWT(jwt)
			if err != nil {
				if errors.Is(err, services.ErrInvalidJwt) {
					return &AuthError{Code: "invalid_token", ErrorDescription: err.Error()}
				}
				return fmt.Errorf("validate jwt: %w", err)
			}

			actor := Actor{
				UserID:     claims.Subject,
				SessionID:  &claims.SessionId,
				JwtID:      claims.ID,
				AuthMethod: AuthMethodBearer,
			}

			ctx = context.WithValue(ctx, actorContextKey{}, actor)
			ctx = logging.With(ctx, slog.String("user_id", actor.UserID))
			*ai.RequestValidationInput.Request = *ai.RequestValidationInput.Request.WithContext(ctx)

			return nil
		default:
			return fmt.Errorf("unsupported security scheme: %v", ai.SecuritySchemeName)
		}
	}
}

func requestLogger(baseLogger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a logger with metadata about that request
			reqLogger := baseLogger.With(
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("req_id", middleware.GetReqID(r.Context())),
			)

			ctxWithLogger := logging.NewContextWithLogger(r.Context(), reqLogger) // Insert that logger into the request context
			requestHijacker := middleware.NewWrapResponseWriter(w, r.ProtoMajor)  // Wrap the writer into some hijacking stuff so I can observe the request results

			start := time.Now()
			next.ServeHTTP(requestHijacker, r.WithContext(ctxWithLogger)) // Run the next middlewares and the http handler

			// Get the request results and log them
			status := requestHijacker.Status()
			duration := time.Since(start)

			var logLevel slog.Level
			switch {
			case status >= 500:
				logLevel = slog.LevelError
			case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests:
				logLevel = slog.LevelWarn
			default:
				logLevel = slog.LevelDebug
			}

			finalLogger := logging.LoggerFromContext(ctxWithLogger) // Get the hydrated logger
			finalLogger.Log(ctxWithLogger, logLevel, "http request",
				slog.Int("status", status),
				slog.Duration("duration", duration),
			)
		})
	}
}

func strictServerOperationLogger(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		ctx = logging.With(ctx, slog.String("op", operationID))
		return f(ctx, w, r, request)
	}
}

func GetClientCountry(ctx context.Context) string {
	if v, ok := ctx.Value("clientCountry").(string); ok {
		return v
	}
	return ""
}

func GetActorFromContext(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(actorContextKey{}).(Actor)
	return actor, ok
}

func NewRouter(s *Server) (http.Handler, error) {
	r := chi.NewRouter()

	// Filtering
	corsMiddleware := cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           1200,
	})
	r.Use(middleware.AllowContentEncoding("identity"))

	// Tracing
	reqId := middleware.RequestID
	if s.config.Server.IPHeader != "" {
		r.Use(middleware.ClientIPFromHeader(s.config.Server.IPHeader))
	}
	if s.config.Server.GeoHeader != "" {
		r.Use(clientCountryFromHeader(s.config.Server.GeoHeader))
	}

	// Logging
	logger := requestLogger(s.logger)

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
		Options: openapi3filter.Options{
			AuthenticationFunc: makeAuthenticationFunc(s.tokens),
		},
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

	strictHandler := NewStrictHandlerWithOptions(s, []StrictMiddlewareFunc{strictServerOperationLogger}, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			logging.With(r.Context(), slog.Any("error", err))
			writeServerError(w)
		},
	})

	for providerID := range s.config.Auth.Providers {
		s.logger.Debug("registering oauth provider",
			slog.String("provider", providerID),
			slog.String("callback", s.config.Auth.Providers[providerID].CallbackPath),
		)
		handler := s.newOAuthCallbackHandler(providerID)
		r.Get(s.config.Auth.Providers[providerID].CallbackPath, handler)
	}

	handler := HandlerFromMux(strictHandler, r)
	handler = validator(handler)
	handler = corsMiddleware(handler)
	handler = logger(handler)
	handler = reqId(handler)

	return handler, nil
}
