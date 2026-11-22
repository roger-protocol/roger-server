-- +goose Up
CREATE TABLE workspaces(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_personal BOOL NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE workspace_members(
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    joined_at TEXT NOT NULL,
    PRIMARY KEY (user_id, workspace_id)
);
CREATE INDEX idx_workspace_members_workspace_id ON workspace_members(workspace_id);

-- Enforce only one personal workspace per user
CREATE UNIQUE INDEX idx_workspace_personal_members
ON workspaces(created_by)
WHERE is_personal = true;

-- Block member modification on personal workspaces
-- +goose StatementBegin
CREATE TRIGGER block_personal_members_update
BEFORE UPDATE ON workspace_members
WHEN EXISTS (
    SELECT 1 FROM workspaces
    WHERE id = OLD.workspace_id AND is_personal = true
)
BEGIN
    SELECT RAISE(ABORT, 'personal workspace memberships cannot be modified');
END;
-- +goose StatementEnd

-- Enforce only one user in personal workspaces
-- +goose StatementBegin
CREATE TRIGGER prevent_multiple_personal_members
BEFORE INSERT ON workspace_members
WHEN EXISTS (
    SELECT 1 FROM workspaces
    WHERE id = NEW.workspace_id AND is_personal = true
)
AND EXISTS (
    SELECT 1 FROM workspace_members
    WHERE workspace_id = NEW.workspace_id
)
BEGIN
    SELECT RAISE(ABORT, 'personal workspaces can only have one member');
END;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS workspace_members;
