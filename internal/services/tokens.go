package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/roger-protocol/roger-server/internal/cache"
	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

var (
	ErrInvalidJwt           = errors.New("invalid jwt")
	ErrInvalidJwtSigningAlg = fmt.Errorf("%w: invalid jwt signing algorithm (expected ES256)", ErrInvalidJwt)
	ErrInvalidJwtSignature  = fmt.Errorf("%w: invalid jwt signature", ErrInvalidJwt)
	ErrJwtMalformed         = fmt.Errorf("%w: invalid or malformed jwt", ErrInvalidJwt)
	ErrJwtExpired           = fmt.Errorf("%w: jwt has expired", ErrInvalidJwt)
	ErrJwtRevoked           = fmt.Errorf("%w: jwt was revoked", ErrInvalidJwt)
)

type TokenService struct {
	logger       *slog.Logger
	config       *config.Config
	revokedCache *cache.Cache[string, struct{}]
}

func NewTokenService(logger *slog.Logger, cfg *config.Config) *TokenService {
	serviceLogger := logger.With(slog.String("service", "tokens"))
	revokedCache := cache.New[string, struct{}](JwtTTL, serviceLogger.With(slog.String("cache", "revoked_jwts")))
	return &TokenService{logger: serviceLogger, config: cfg, revokedCache: revokedCache}
}

func (s *TokenService) Close() {
	s.revokedCache.Close()
}

const JwtTTL = 15 * time.Minute

type JWTClaims struct {
	jwt.RegisteredClaims
	SessionId     string  `json:"sid"`
	Username      string  `json:"username"`
	Email         *string `json:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}

func (s *TokenService) CreateJWT(user db.User, sessionId string) (string, JWTClaims, error) {
	now := time.Now().UTC()

	var emailPtr *string
	var emailVerifiedPtr *bool
	if user.Email.Valid {
		emailPtr = &user.Email.String
		if user.EmailVerified.Valid {
			isVerified := user.EmailVerified.Int64 == 1
			emailVerifiedPtr = &isVerified
		}
	}

	claims := JWTClaims{
		ID:            crypto.GenerateID("rgr_jti"),
		Issuer:        s.config.Server.ServerURL,
		Subject:       user.ID,
		IssuedAt:      jwt.NewNumericDate(now),
		ExpiresAt:     jwt.NewNumericDate(now.Add(JwtTTL)),
		SessionId:     sessionId,
		Username:      user.Username,
		Email:         emailPtr,
		EmailVerified: emailVerifiedPtr,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedJwt, err := token.SignedString(s.config.Auth.JWTPrivateKey)
	if err != nil {
		return "", JWTClaims{}, fmt.Errorf("signing jwt: %w", err)
	}
	return signedJwt, claims, nil
}

func (s *TokenService) ValidateJWT(jwtString string) (JWTClaims, error) {
	claims, err := s.ParseJwt(jwtString)
	if err != nil {
		return JWTClaims{}, err
	}

	if s.revokedCache.Has(claims.ID) {
		return JWTClaims{}, ErrJwtRevoked
	}

	return claims, nil
}

func (s *TokenService) ParseJwt(jwtString string, extraOpts ...jwt.ParserOption) (JWTClaims, error) {
	opts := append([]jwt.ParserOption{jwt.WithIssuer(s.config.Server.ServerURL)}, extraOpts...)
	token, err := jwt.ParseWithClaims(
		jwtString,
		&JWTClaims{},
		func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != "ES256" {
				return nil, ErrInvalidJwtSigningAlg
			}
			return s.config.Auth.JWTPublicKey, nil
		},
		opts...,
	)

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return JWTClaims{}, ErrInvalidJwtSignature
		case errors.Is(err, jwt.ErrTokenExpired):
			return JWTClaims{}, ErrJwtExpired
		case errors.Is(err, jwt.ErrTokenMalformed),
			errors.Is(err, jwt.ErrTokenNotValidYet),
			errors.Is(err, jwt.ErrTokenInvalidClaims),
			errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return JWTClaims{}, ErrJwtMalformed
		default:
			return JWTClaims{}, fmt.Errorf("parse jwt: %w", err)
		}
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return JWTClaims{}, ErrJwtMalformed
	}
	return *claims, nil
}

func (s *TokenService) RevokeJwt(ctx context.Context, jti string) {
	if jti == "" {
		return
	}
	s.revokedCache.Set(jti, struct{}{}, JwtTTL)
}
