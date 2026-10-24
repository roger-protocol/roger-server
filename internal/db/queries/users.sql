-- name: GetUserByID :one
SELECT * FROM users
WHERE id = ?
LIMIT 1;

-- name: GetUserByProvider :one
SELECT u.*
FROM users u
JOIN providers p ON u.id = p.user_id
WHERE p.provider_id = ? AND p.subject = ?
LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (
    id,
    username,
    email,
    email_verified,
    created_at,
    updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateUsername :one
UPDATE users
SET
    username = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: UpdateEmail :one
UPDATE users
SET
    email = ?,
    email_verified = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: DeleteUser :one
DELETE FROM users
WHERE id = ?
LIMIT 1
RETURNING *;
