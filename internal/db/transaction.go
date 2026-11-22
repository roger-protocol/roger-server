package db

import (
	"context"
	"database/sql"
)

func WithTransaction(ctx context.Context, db *sql.DB, q *Queries, fn func(qtx *Queries) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := q.WithTx(tx)

	if err := fn(qtx); err != nil {
		return err
	}

	return tx.Commit()
}
