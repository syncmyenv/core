-- Local vault index. Lives in ~/.syncmyenv (0700), never synced as-is.
--
-- Paths are plaintext here on purpose: the daemon must know what to watch
-- without your password, and the files themselves sit on this same disk.
-- Contents are ALWAYS sealed. Anything sent to a remote is sealed too.

CREATE TABLE files (
    id           TEXT PRIMARY KEY,
    path         TEXT NOT NULL UNIQUE,     -- absolute, cleaned
    project      TEXT NOT NULL,            -- git root name, else parent dir
    protected_at INTEGER NOT NULL,
    removed_at   INTEGER                   -- unprotected (history kept)
);

CREATE TABLE revisions (
    id         TEXT PRIMARY KEY,
    file_id    TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,           -- 1, 2, 3… per file
    change_mac BLOB NOT NULL,              -- HMAC(local change key, plaintext)
    size       INTEGER NOT NULL,           -- plaintext bytes
    sealed     BLOB NOT NULL,              -- age ciphertext (vault recipient)
    source     TEXT NOT NULL CHECK (source IN ('protect', 'snapshot', 'restore')),
    device     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (file_id, seq)
);
CREATE INDEX revisions_file ON revisions(file_id, seq DESC);
