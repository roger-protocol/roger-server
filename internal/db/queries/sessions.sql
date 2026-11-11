-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id,
    ip_address,
    country,
    client_name,
    refresh_token_hash,
    access_token_jti,
    access_token_expires_at,
    created_at,
    last_used_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = ?
LIMIT 1;

-- name: GetSessionFromRefreshToken :one
SELECT * FROM sessions
WHERE refresh_token_hash = ?
LIMIT 1;

-- name: GetUserSessions :many
SELECT * FROM sessions
WHERE user_id = ?;

-- name: RefreshSession :one
UPDATE sessions
SET
    access_token_jti = ?,
    access_token_expires_at = ?,
    ip_address = ?,
    country = ?,
    last_used_at = ?
WHERE id = ?
RETURNING *;

-- name: RevokeSession :one
DELETE FROM sessions
WHERE id = ?
RETURNING *;

-- name: RevokeAllSessionsExcept :many
DELETE FROM sessions
WHERE user_id = ? AND id != ?
RETURNING *;
