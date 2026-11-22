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
