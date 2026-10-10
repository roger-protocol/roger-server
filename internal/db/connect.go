package db

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embededMigrations embed.FS

func Open(path string) (db *sql.DB, err error) {
	dsn := path + "?" + "_pragma=journal_mode(WAL)&" + "_pragma=synchronous(NORMAL)&" + "_pragma=busy_timeout(5000)&" + "_pragma=foreign_keys(ON)"
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Close the DB if there is any error past this point
	defer func() {
		if err != nil && db != nil {
			if closeErr := db.Close(); closeErr != nil {
				err = fmt.Errorf("%w (failed to close db: %v)", err, closeErr)
			}
		}
	}()

	db.SetMaxOpenConns(1)

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite db: %w", err)
	}

	if err = runMigrations(db); err != nil {
		return nil, fmt.Errorf("run db migrations: %w", err)
	}

	return db, nil
}

func runMigrations(db *sql.DB) error {
	goose.SetBaseFS(embededMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
