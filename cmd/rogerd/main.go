package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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
	server := api.NewServer(database, queries, cfg)
	router, err := api.NewRouter(server)

	if err != nil {
		log.Fatalf("failed to setup router: %v", err)
	}

	go func() {
		log.Printf("Listening on port %s...", cfg.Server.Addr)

		if err := http.ListenAndServe(cfg.Server.Addr, router); err != nil {
			log.Fatalf("failed to open http server: %v", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("OK")

	if err := database.Close(); err != nil {
		log.Printf("Couldn't close database cleanly. Current WAL checkpoint wasn't commited")
	}

}
