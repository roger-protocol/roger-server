package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/gobwas/glob"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/convert"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
	"golang.org/x/oauth2"
)

var (
	ErrUnsupportedProvider = errors.New("unsupported provider")
	ErrIllegalRedirectUri  = errors.New("illegal redirect uri")
)

type AuthService struct {
	db      *sql.DB
	config  *config.Config
	queries *db.Queries
}

func NewAuthService(db *sql.DB, q *db.Queries, cfg *config.Config) *AuthService {
	return &AuthService{db: db, config: cfg, queries: q}
}

const oauthStateTTL = 5 * time.Minute

type oauthState struct {
	ClientState         string `json:"cs"`
	CodeChallenge       string `json:"cc"`
	CodeChallengeMethod string `json:"ccm"`
	RedirectURI         string `json:"ru"`
	IssuedAt            string `json:"iat"`
}

type tokenClaims struct {
	Username      string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	jwt.RegisteredClaims
}

func isValidRedirectUri(redirectUri string, allowed []*glob.Pattern) bool {
	if _, err := url.ParseRequestURI(redirectUri); err != nil {
		return false
	}
	for _, g := range allowed {
		if g.Match(redirectUri) {
			return true
		}
	}
	return false
}

func (s *AuthService) ForgeState(clientState string, codeChallenge string, codeChallengeMethod string, clientRedirectUri string) (string, error) {
	stateData := oauthState{
		ClientState:         clientState,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         clientRedirectUri,
		IssuedAt:            strconv.FormatInt(time.Now().Unix(), 10),
	}

	stateBytes, err := json.Marshal(stateData)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}

	encryptedState, err := crypto.AESEncrypt(s.config.Server.DBEncryptionKey, stateBytes)
	if err != nil {
		return "", fmt.Errorf("encrypt state data: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(encryptedState), nil
}

func (s *AuthService) DecodeState(encodedState string) (oauthState, error) {
	stateBytes, err := base64.RawURLEncoding.DecodeString(encodedState)
	if err != nil {
		return oauthState{}, fmt.Errorf("decode base64 state: %w", err)
	}

	decryptedState, err := crypto.AESDecrypt(s.config.Server.DBEncryptionKey, stateBytes)
	if err != nil {
		return oauthState{}, fmt.Errorf("decrypt state: %w", err)
	}

	var state oauthState
	if err := json.Unmarshal(decryptedState, &state); err != nil {
		return oauthState{}, fmt.Errorf("unmarshal state: %w", err)
	}

	issuedAtUnix, err := strconv.ParseInt(state.IssuedAt, 10, 64)
	if err != nil {
		return oauthState{}, fmt.Errorf("invalid state issued_at timestamp: %w", err)
	}

	issuedAt := time.Unix(issuedAtUnix, 0)
	if time.Since(issuedAt) > oauthStateTTL {
		return oauthState{}, errors.New("state token expired")
	}

	return state, nil
}

func (s *AuthService) GetProviderRedirectURL(providerID string, codeChallenge string, codeChallengeMethod string, clientState string, clientRedirectUri string) (string, error) {
	providerCfg, ok := s.config.Auth.Providers[providerID]
	if !ok {
		return "", ErrUnsupportedProvider
	}

	if !isValidRedirectUri(clientRedirectUri, s.config.Auth.CompiledRedirectGlobs) {
		return "", ErrIllegalRedirectUri
	}

	redirectUri, err := url.JoinPath(s.config.Server.ServerURL, providerCfg.CallbackPath)
	if err != nil {
		return "", fmt.Errorf("create redirect uri: %w", err)
	}

	state, err := s.ForgeState(clientState, codeChallenge, codeChallengeMethod, clientRedirectUri)
	if err != nil {
		return "", fmt.Errorf("forge state: %w", err)
	}

	conf := oauth2.Config{
		ClientID: providerCfg.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL: providerCfg.AuthURL,
		},
		RedirectURL: redirectUri,
		Scopes:      providerCfg.Scopes,
	}

	return conf.AuthCodeURL(state), nil
}

func (s *AuthService) ExchangeProviderCode(ctx context.Context, providerID string, code string) (tokenClaims, error) {
	providerCfg, ok := s.config.Auth.Providers[providerID]
	if !ok {
		return tokenClaims{}, ErrUnsupportedProvider
	}

	redirectUri, err := url.JoinPath(s.config.Server.ServerURL, providerCfg.CallbackPath)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("create redirect uri: %w", err)
	}

	conf := oauth2.Config{
		ClientID:     providerCfg.ClientID,
		ClientSecret: providerCfg.ClientSecret,
		RedirectURL:  redirectUri,
		Endpoint: oauth2.Endpoint{
			TokenURL: providerCfg.TokenURL,
		},
	}

	// Exchange the code for a token
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("oauth2 code exchange: %w", err)
	}

	// Extract the id token containing the OAuth2 informations
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return tokenClaims{}, errors.New("missing id_token")
	}

	// Unmarshal the id token into a claim struct
	var claims tokenClaims
	_, _, err = jwt.NewParser().ParseUnverified(rawIDToken, &claims)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("parse id_token: %w", err)
	}

	return claims, nil
}

func (s *AuthService) CreateUser(ctx context.Context, q *db.Queries, username string, email string, email_verified bool) (db.User, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	newUser, err := q.CreateUser(ctx, db.CreateUserParams{
		ID:            crypto.GenerateID("rgr_usr"),
		Username:      username,
		Email:         convert.ToNullString(email),
		EmailVerified: convert.BoolToNullInt64(email_verified, email != ""),
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	if err != nil {
		return db.User{}, fmt.Errorf("create user: %w", err)
	}

	return newUser, nil
}

func (s *AuthService) LinkProviderToUser(ctx context.Context, q *db.Queries, userID string, providerID string, subject string, claims *tokenClaims) (db.Provider, error) {
	// Prepare the raw profile
	var rawClaims sql.NullString
	if claims != nil {
		claimsBytes, err := json.Marshal(claims)
		if err != nil {
			return db.Provider{}, fmt.Errorf("marshal claims: %w", err)
		}
		rawClaims = convert.ToNullString(string(claimsBytes))
	}

	// Create the provider row
	now := time.Now().UTC().Format(time.RFC3339)
	newProvider, err := q.CreateProvider(ctx, db.CreateProviderParams{
		ID:         crypto.GenerateID("rgr_prv"),
		UserID:     userID,
		ProviderID: providerID,
		Subject:    subject,
		RawClaims:  rawClaims,
		CreatedAt:  now,
		LastUsed:   now,
	})
	if err != nil {
		return db.Provider{}, fmt.Errorf("create provider: %w", err)
	}
	return newProvider, nil
}

func (s *AuthService) GetUserFromProviderCode(ctx context.Context, providerID string, code string) (db.User, error) {
	claims, err := s.ExchangeProviderCode(ctx, providerID, code)
	if err != nil {
		return db.User{}, fmt.Errorf("exchange code: %w", err)
	}

	// Check if a provider exists with the given provider id and subject
	provider, err := s.queries.GetProviderFromSubject(ctx, db.GetProviderFromSubjectParams{ProviderID: providerID, Subject: claims.Subject})
	if err == nil {
		// Update that provider last used timestamp
		provider, err := s.queries.SetProviderLastUsed(ctx, db.SetProviderLastUsedParams{ID: provider.ID, LastUsed: time.Now().UTC().Format(time.RFC3339)})
		if err != nil {
			return db.User{}, fmt.Errorf("set provider last used: %w", err)
		}

		// Get the user linked to that provider
		user, err := s.queries.GetUserByID(ctx, provider.UserID)
		if err != nil {
			return db.User{}, fmt.Errorf("retrieve user by id: %w", err)
		}
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.User{}, fmt.Errorf("retrieve provider from subject: %w", err)
	}

	// The user doesn't exist yet -> create it
	// Prepare the username
	username := claims.Username
	if username == "" {
		if claims.Email != "" {
			username = claims.Email
		} else {
			username = crypto.GenerateID("user")
		}
	}

	// Create transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return db.User{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback the transaction if it wasn't commited
	qtx := s.queries.WithTx(tx)

	// Create the user in the transaction
	newUser, err := s.CreateUser(ctx, qtx, username, claims.Email, claims.EmailVerified)
	if err != nil {
		return db.User{}, err
	}

	// Link the provider to the new user in the transaction
	_, err = s.LinkProviderToUser(ctx, qtx, newUser.ID, providerID, claims.Subject, &claims)
	if err != nil {
		return db.User{}, err
	}

	// Commit the transaction to the db
	if err := tx.Commit(); err != nil {
		return db.User{}, fmt.Errorf("commit transaction: %w", err)
	}

	return newUser, nil
}

func (s *AuthService) CreateAuthorizationCode(ctx context.Context, q *db.Queries, userId string, codeChallenge string, codeChallengeMethod string, redirectUri string) (string, db.AuthorizationCode, error) {
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
