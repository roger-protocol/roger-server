package services

import (
	"context"
	"database/sql"
	"encoding/base64"
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
	ErrUnsupportedProvider        = errors.New("unsupported provider")
	ErrIllegalRedirectUri         = errors.New("illegal redirect uri")
	ErrUnknownCodeChallengeMethod = errors.New("unknown code challenge method")
)

const oauthStateTTL = 5 * time.Minute

type oauthState struct {
	ClientState         *string `json:"cs"`
	CodeChallenge       string  `json:"cc"`
	CodeChallengeMethod string  `json:"ccm"`
	RedirectURI         string  `json:"ru"`
	IssuedAt            string  `json:"iat"`
}

type providerClaims struct {
	Username      string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	jwt.RegisteredClaims
}

type ProviderService struct {
	config *config.Config
}

func NewProviderService(cfg *config.Config) *ProviderService {
	return &ProviderService{config: cfg}
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

func (s *ProviderService) ForgeState(clientState *string, codeChallenge string, codeChallengeMethod string, clientRedirectUri string) (string, error) {
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
func (s *ProviderService) DecodeState(encodedState string) (oauthState, error) {
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

func (s *ProviderService) GetProviderRedirectURL(providerID string, codeChallenge string, codeChallengeMethod string, clientState *string, clientRedirectUri string) (string, error) {
	providerCfg, ok := s.config.Auth.Providers[providerID]
	if !ok {
		return "", ErrUnsupportedProvider
	}

	if !isValidRedirectUri(clientRedirectUri, s.config.Auth.CompiledRedirectGlobs) {
		return "", ErrIllegalRedirectUri
	}

	if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		return "", ErrUnknownCodeChallengeMethod
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
func (s *ProviderService) ExchangeAuthorizationCode(ctx context.Context, providerID string, code string) (providerClaims, error) {
	providerCfg, ok := s.config.Auth.Providers[providerID]
	if !ok {
		return providerClaims{}, ErrUnsupportedProvider
	}

	redirectUri, err := url.JoinPath(s.config.Server.ServerURL, providerCfg.CallbackPath)
	if err != nil {
		return providerClaims{}, fmt.Errorf("create redirect uri: %w", err)
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
		return providerClaims{}, fmt.Errorf("oauth2 code exchange: %w", err)
	}

	// Extract the id token containing the OAuth2 informations
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return providerClaims{}, errors.New("missing id_token")
	}

	// Unmarshal the id token into a claim struct
	var claims providerClaims
	_, _, err = jwt.NewParser().ParseUnverified(rawIDToken, &claims)
	if err != nil {
		return providerClaims{}, fmt.Errorf("parse id_token: %w", err)
	}

	return claims, nil
}
func (s *ProviderService) LinkProviderToUser(ctx context.Context, q *db.Queries, userID string, providerID string, subject string, claims *providerClaims) (db.Provider, error) {
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
