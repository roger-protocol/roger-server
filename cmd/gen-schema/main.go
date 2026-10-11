package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/roger-protocol/roger-server/internal/config"
)

const SCHEMA_PATH = "dist/config.schema.json"

func main() {
	r := &jsonschema.Reflector{}

	if err := r.AddGoComments("github.com/roger-protocol/roger-server", "internal/config"); err != nil {
		log.Fatalf("failed to load go comments: %v", err)
	}

	// Replace the annoying windows backslashes :(
	normalizedMap := make(map[string]string, len(r.CommentMap))
	for k, v := range r.CommentMap {
		k = strings.ReplaceAll(k, `\`, "/")
		normalizedMap[k] = v
	}
	r.CommentMap = normalizedMap

	schema := r.Reflect(&config.Config{})
	schema.Title = "Rogerd Configuration File"
	schema.Description = "JSON schema for the rogerd yaml configuration file"

	if err := os.MkdirAll(filepath.Dir(SCHEMA_PATH), 0755); err != nil {
		log.Fatalf("failed to create parent directory: %v", err)
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal schema, %v", err)
	}
	if err := os.WriteFile(SCHEMA_PATH, data, 0644); err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	log.Printf("Generated schema for the rogerd config file under " + SCHEMA_PATH)
}
