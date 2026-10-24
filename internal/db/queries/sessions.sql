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

-- name: GetUserSessions :many
SELECT * FROM sessions
WHERE user_id = ?;

-- name: UpdateSessionFromRefreshToken :one
UPDATE sessions
SET
    access_token_jti = ?,
    access_token_expires_at = ?,
    last_used_at = ?
WHERE refresh_token_hash = ?
RETURNING *;

-- name: RevokeSession :one
DELETE FROM sessions
WHERE id = ?
RETURNING *;

-- name: RevokeAllSessionsExcept :many
DELETE FROM sessions
WHERE user_id = ? AND id != ?
RETURNING *;
