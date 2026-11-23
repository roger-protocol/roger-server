package services

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/roger-protocol/roger-server/internal/cache"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

var (
	ErrInvalidGrant             = errors.New("invalid grant")
	ErrRedirectUriMismatch      = fmt.Errorf("%w: redirect uri mismatch", ErrInvalidGrant)
	ErrInvalidAuthorizationCode = fmt.Errorf("%w: invalid authorization code", ErrInvalidGrant)
	ErrInvalidRefreshToken      = fmt.Errorf("%w: invalid refresh token", ErrInvalidGrant)
	ErrInvalidCodeVerifier      = fmt.Errorf("%w: invalid code verifier", ErrInvalidGrant)
	ErrAuthorizationCodeExpired = fmt.Errorf("%w: expired authorization code", ErrInvalidGrant)
)

type OAuthService struct {
	logger    *slog.Logger
	db        *sql.DB
	providers *ProviderService
	users     *UserService
	acStore   *cache.Cache[string, AuthorizationCode]
}

func NewOAuthService(logger *slog.Logger, db *sql.DB, pvd *ProviderService, usr *UserService) *OAuthService {
	serviceLogger := logger.With(slog.String("service", "oauth"))
	acStore := cache.New[string, AuthorizationCode](AuthorizationCodeTTL, serviceLogger.With(slog.String("cache", "authorization_codes")))
	return &OAuthService{logger: serviceLogger, db: db, providers: pvd, users: usr, acStore: acStore}
}

const AuthorizationCodeTTL = 5 * time.Minute

type AuthorizationCode struct {
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectUri         string
}

func (s *OAuthService) CreateAuthorizationCode(ctx context.Context, q *db.Queries, userId string, codeChallenge string, codeChallengeMethod string, redirectUri string) string {
	acId := crypto.GenerateID("rgr_ac")
	acIdHash := crypto.Hash256([]byte(acId), hex.EncodeToString)

	newAc := AuthorizationCode{
		UserID:              userId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectUri:         redirectUri,
	}

	s.acStore.Set(acIdHash, newAc, AuthorizationCodeTTL)

	return acId
}

// Possible Error Codes:
// - ErrInvalidAuthorizationCode
// - ErrAuthorizationCodeExpired
// - ErrRedirectUriMismatch
// - ErrInvalidCodeVerifier
func (s *OAuthService) ConsumeAuthorizationCode(ctx context.Context, q *db.Queries, authorizationCode string, redirectUri string, codeVerifier string) (db.User, error) {
	// Hash the authorizationCode and get it's details
	acHash := crypto.Hash256([]byte(authorizationCode), hex.EncodeToString)
	ac, exists := s.acStore.Get(acHash)
	if !exists {
		return db.User{}, ErrInvalidAuthorizationCode
	}
	s.acStore.Delete(acHash)

	// Check if the redirect uri matches the previous redirect uri
	if ac.RedirectUri != redirectUri {
		return db.User{}, ErrRedirectUriMismatch
	}

	// Check if the code verifier is valid
	var codeChallenge string
	switch ac.CodeChallengeMethod {
	case "S256":
		codeChallenge = crypto.Hash256([]byte(codeVerifier), base64.RawURLEncoding.EncodeToString)
	case "plain":
		codeChallenge = codeVerifier
	default:
		return db.User{}, errors.New("invalid code challenge method")
	}

	if subtle.ConstantTimeCompare([]byte(ac.CodeChallenge), []byte(codeChallenge)) != 1 { // Use ConstantTimeCompare for security ig
		return db.User{}, ErrInvalidCodeVerifier
	}

	user, err := q.GetUserByID(ctx, ac.UserID)
	if err != nil {
		return db.User{}, fmt.Errorf("fetch user profile: %w", err)
	}

	return user, nil
}

func (s *OAuthService) HandleOAuthCallback(ctx context.Context, q *db.Queries, providerID string, state oauthState, code string) (string, error) {
	// Create transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	qtx := q.WithTx(tx)

	// Exchange provider code for a provider jwt claims
	providerClaims, err := s.providers.ExchangeAuthorizationCode(ctx, providerID, code)
	if err != nil {
		return "", fmt.Errorf("exchange authorization code: %w", err)
	}

	// Get the user linked to that provider or create it
	user, created, err := s.users.GetOrCreateUserFromProviderClaimsTx(ctx, qtx, providerID, providerClaims)
	if err != nil {
		return "", fmt.Errorf("get user from provider claims: %w", err)
	}

	// If the user was newly created, link the provider to the user
	if created {
		_, err := s.providers.LinkProviderToUser(ctx, qtx, user.ID, providerID, providerClaims.Subject, &providerClaims)
		if err != nil {
			return "", fmt.Errorf("link provider to user: %w", err)
		}
	}

	// Create an authorization code
	ac := s.CreateAuthorizationCode(ctx, qtx, user.ID, state.CodeChallenge, state.CodeChallengeMethod, state.RedirectURI)

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("commit transaction: %w", err)
	}

	return ac, nil
}
