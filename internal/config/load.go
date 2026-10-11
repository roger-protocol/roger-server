package config

import (
	"fmt"
	"os"

	"github.com/a8m/envsubst"
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

	return config, nil
}
