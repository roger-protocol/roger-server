-- name: GetProvider :one
SELECT * FROM providers
WHERE id = ?
LIMIT 1;

-- name: GetProviderFromSubject :one
SELECT * FROM providers
WHERE subject = ? AND provider_id = ?
LIMIT 1;

-- name: GetUserProviders :many
SELECT * FROM providers
WHERE user_id = ?;

-- name: DeleteProvider :one
DELETE FROM providers
WHERE id = ?
LIMIT 1
RETURNING *;

-- name: CreateProvider :one
INSERT INTO providers (
    id,
    user_id,
    provider_id,
    subject,
    raw_claims,
    created_at,
    last_used
) VALUES (
    ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: SetProviderLastUsed :one
UPDATE providers
SET
    last_used = ?
WHERE id = ?
RETURNING *;

-- name: SetProviderRawClaims :one
UPDATE providers
SET
    raw_claims = ?
WHERE id = ?
RETURNING *;
