package config

import (
	"fmt"
	"os"

	"github.com/a8m/envsubst"
	"github.com/gobwas/glob"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	result, err := envsubst.Bytes(data)
	if err != nil {
		return nil, fmt.Errorf("inject env variables: %w", err)
	}

	config := &Config{}
	if err := yaml.Unmarshal(result, config); err != nil {
		return nil, fmt.Errorf("parsing yaml config: %w", err)
	}

	// Load private key
	jwt_sk, err := os.ReadFile(config.Auth.JWTPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading jwt private key: %w", err)
	}
	parsed_sk, err := jwt.ParseECPrivateKeyFromPEM(jwt_sk)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	config.Auth.JWTPrivateKey = parsed_sk

	// Load public key
	jwt_pk, err := os.ReadFile(config.Auth.JWTPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading jwt public key: %w", err)
	}
	config.Features.Auth.JwtPublicKey = string(jwt_pk)
	parsed_pk, err := jwt.ParseECPublicKeyFromPEM(jwt_pk)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	config.Auth.JWTPublicKey = parsed_pk

	// Compile AllowedRedirectURIs patterns
	compiled := make([]*glob.Pattern, 0, len(config.Auth.AllowedRedirectURIs))
	for _, pattern := range config.Auth.AllowedRedirectURIs {
		g, err := glob.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile redirect uri pattern %v: %w", pattern, err)
		}
		compiled = append(compiled, g)
	}
	config.Auth.CompiledRedirectGlobs = compiled

	return config, nil
}
