-- name: CreateAuthorizationCode :one
INSERT INTO authorization_codes (
    id_hash,
    user_id,
    code_challenge,
    code_challenge_method,
    redirect_uri,
    created_at
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: DeleteAuthorizationCode :one
DELETE FROM authorization_codes
WHERE id_hash = ?
LIMIT 1
RETURNING *;

-- GetAuthorizationCodeDetails :one
SELECT * FROM authorization_codes
WHERE id_hash = ?
LIMIT 1;
