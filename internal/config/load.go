package config

import (
	"fmt"
	"os"

	"github.com/a8m/envsubst"
	"github.com/gobwas/glob"
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

	jwt_pk, err := os.ReadFile(config.Auth.JWTPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading jwt public key: %w", err)
	}
	config.Features.Auth.JwtPublicKey = string(jwt_pk)

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
