-- Sync bookkeeping.
ALTER TABLE revisions ADD COLUMN object_id TEXT;       -- hex(sha256(sealed)), set when pushed/imported
ALTER TABLE revisions ADD COLUMN pushed_at INTEGER;    -- NULL = not yet on the server
ALTER TABLE revisions ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'; -- 'local' or remote device id
CREATE INDEX revisions_pending ON revisions(pushed_at) WHERE pushed_at IS NULL;
CREATE INDEX revisions_object ON revisions(file_id, object_id);

CREATE TABLE sync_state (
    key   TEXT PRIMARY KEY,   -- vault_id, device_seq, pull_cursor
    value TEXT NOT NULL
);
