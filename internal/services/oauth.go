package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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
	db        *sql.DB
	providers *ProviderService
	users     *UserService
}

func NewOAuthService(db *sql.DB, pvd *ProviderService, usr *UserService) *OAuthService {
	return &OAuthService{db: db, providers: pvd, users: usr}
}

const AuthorizationCodeTTL = 5 * time.Minute

func (s *OAuthService) CreateAuthorizationCode(ctx context.Context, q *db.Queries, userId string, codeChallenge string, codeChallengeMethod string, redirectUri string) (string, db.AuthorizationCode, error) {
	id := crypto.GenerateID("rgr_ac")
	idHashBytes := sha256.Sum256([]byte(id))

	newAc, err := q.CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
		IDHash:              hex.EncodeToString(idHashBytes[:]),
		UserID:              userId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectUri:         redirectUri,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
	})

	if err != nil {
		return "", db.AuthorizationCode{}, fmt.Errorf("create authorization code: %w", err)
	}

	return id, newAc, nil
}

// Possible Error Codes:
// - ErrInvalidAuthorizationCode
// - ErrAuthorizationCodeExpired
// - ErrRedirectUriMismatch
// - ErrInvalidCodeVerifier
func (s *OAuthService) ConsumeAuthorizationCode(ctx context.Context, q *db.Queries, authorizationCode string, redirectUri string, codeVerifier string) (db.User, error) {
	// Hash the authorizationCode and get it's details
	acHash := crypto.Hash256([]byte(authorizationCode), hex.EncodeToString)
	acDetails, err := q.DeleteAuthorizationCode(ctx, acHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.User{}, ErrInvalidAuthorizationCode
		}
		return db.User{}, fmt.Errorf("delete authorization code: %w", err)
	}

	// Check if the authorization code has expired
	createdAt, err := time.Parse(time.RFC3339Nano, acDetails.CreatedAt)
	if err != nil {
		return db.User{}, fmt.Errorf("parse creation date: %w", err)
	}
	if createdAt.Add(AuthorizationCodeTTL).Before(time.Now().UTC()) {
		return db.User{}, ErrAuthorizationCodeExpired
	}

	// Check if the redirect uri matches the previous redirect uri
	if acDetails.RedirectUri != redirectUri {
		return db.User{}, ErrRedirectUriMismatch
	}

	// Check if the code verifier is valid
	var codeChallenge string
	switch acDetails.CodeChallengeMethod {
	case "S256":
		codeChallenge = crypto.Hash256([]byte(codeVerifier), base64.RawURLEncoding.EncodeToString)
	case "plain":
		codeChallenge = codeVerifier
	default:
		return db.User{}, fmt.Errorf("invalid code challenge method: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(acDetails.CodeChallenge), []byte(codeChallenge)) != 1 { // Use ConstantTimeCompare for security ig
		return db.User{}, ErrInvalidCodeVerifier
	}

	user, err := q.GetUserByID(ctx, acDetails.UserID)
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
	user, created, err := s.users.GetOrCreateUserFromProviderClaims(ctx, qtx, providerID, providerClaims)
	if err != nil {
		return "", fmt.Errorf("get user from provider claims: %w", err)
	}

	// If the user was newly created, link the provider to the user, else cleanup their old authorization codes
	if created {
		_, err := s.providers.LinkProviderToUser(ctx, qtx, user.ID, providerID, providerClaims.Subject, &providerClaims)
		if err != nil {
			return "", fmt.Errorf("link provider to user: %w", err)
		}
	} else {
		_, err := qtx.DeleteUserAuthorizationCodes(ctx, user.ID)
		if err != nil {
			return "", fmt.Errorf("cleanup user authorization codes: %w", err)
		}
	}

	// Create an authorization code
	ac, _, err := s.CreateAuthorizationCode(ctx, qtx, user.ID, state.CodeChallenge, state.CodeChallengeMethod, state.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("create authorization code: %w", err)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("commit transaction: %w", err)
	}

	return ac, nil
}
