-- name: CreateWorkspace :one
INSERT INTO workspaces (
    id,
    name,
    is_personal,
    created_by,
    created_at
) VALUES (
    ?, ?, ?, ?, ?
)
RETURNING *;

-- name: CreateWorkspaceMember :one
INSERT INTO workspace_members (
    workspace_id,
    user_id,
    role,
    joined_at
) VALUES (
    ?, ?, ?, ?
)
RETURNING *;

-- name: GetPersonalWorkspace :one
SELECT w.*
FROM workspaces w
JOIN workspace_members m ON m.workspace_id = w.id
WHERE m.user_id = ? AND w.is_personal = true
LIMIT 1;
