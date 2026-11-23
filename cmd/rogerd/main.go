package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/roger-protocol/roger-server/internal/api"
	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/db"
	"github.com/roger-protocol/roger-server/internal/logging"
	_ "modernc.org/sqlite"
)

const CONFIG_FILE_PATH = "config.yaml"

func main() {
	if err := run(); err != nil {
		slog.Error("rogerd exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("load env: %w", err)
	}

	cfg, err := config.Load(CONFIG_FILE_PATH)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var logger *slog.Logger
	if cfg.Server.Logging != nil {
		logger = logging.New(cfg.Server.Logging.LogLevel, cfg.Server.Logging.Format)
	} else {
		logger = logging.New("info", "text")
	}

	database, err := db.Open(cfg.Server.DBPath)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer database.Close()

	queries := db.New(database)
	server := api.NewServer(database, queries, cfg, logger)
	defer server.Close()
	router, err := api.NewRouter(server)

	if err != nil {
		return fmt.Errorf("setup router: %w", err)
	}

	go func() {
		logger.Info("rogerd started",
			slog.String("version", cfg.Server.Version),
			slog.String("port", cfg.Server.Addr),
		)

		if err := http.ListenAndServe(cfg.Server.Addr, router); err != nil {
			slog.Error("rogerd exited with error", slog.Any("error", fmt.Errorf("open http server: %w", err)))
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	if err := database.Close(); err != nil {
		return fmt.Errorf("close database (current WAL checkpoint wasn't commited): %w", err)
	}
	return nil
}
