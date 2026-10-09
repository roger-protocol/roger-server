-- +goose Up
CREATE TABLE test (
    id TEXT PRIMARY KEY,
    hello TEXT NOT NULL UNIQUE
);

-- +goose Down
DROP TABLE test;
