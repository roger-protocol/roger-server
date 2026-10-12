package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/roger-protocol/roger-server/internal/api"
	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	_ "modernc.org/sqlite"
)

const CONFIG_FILE_PATH = "config.yaml"

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("failed to load env: %v", err)
	}

	cfg, err := config.Load(CONFIG_FILE_PATH)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Open(cfg.Server.DBPath)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer database.Close()

	queries := db.New(database)
	server := api.NewServer(queries, cfg)
	router := api.NewRouter(server)

	log.Printf("Listening on port %s...", cfg.Server.Addr)

	if err := http.ListenAndServe(cfg.Server.Addr, router); err != nil {
		log.Fatalf("failed to open http server: %v", err)
	}

}
