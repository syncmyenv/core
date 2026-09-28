# Architecture

## Principles

- **Local is the source of truth.** Remote storage is backup, sync and recovery.
- **Only ciphertext leaves the machine** — including paths and project names.
- **Automatic.** After setup, the daemon versions and syncs without prompts.

## Key hierarchy

```text
master password ──argon2id (64MiB,t3,p4)──▶ KEK₁ ─┐
                                                  ├─ XChaCha20-Poly1305 ─▶ vault identity
recovery key (240 bit) ──hkdf-sha256──────▶ KEK₂ ─┘   age hybrid ML-KEM-768 + X25519
                                                              │
                                              vault recipient age1pq1… (public)
                                                              │
                                  daemon seals every revision to the recipient
```

- **Post-quantum**: the vault key is an age *hybrid* identity (ML-KEM-768 + X25519).
  Synced ciphertext lives on remotes for years; hybrid keys stay safe even if it's
  harvested now and attacked with a future quantum computer.
- The daemon only needs the **public** recipient → runs unattended, can't read old secrets.
- `history --show`, `restore`, `share` unlock the identity in memory.
- **MAC key** for change detection/dedup = HKDF(identity, "syncmyenv/v1/mac-key").
  Never a bare hash of plaintext (short values would be brute-forceable).
- Fingerprint (for humans comparing machines): first 8 bytes of SHA-256(recipient),
  shown as `9260:57df:5528:0f29`.

### Key file (`~/.syncmyenv/keys.json`, 0600)

```json
{
  "version": 1,
  "recipient": "age1pq1…",
  "created_at": "…",
  "password": { "kdf": "argon2id", "argon": {"m": 65536, "t": 3, "p": 4}, "salt": "…", "nonce": "…", "ciphertext": "…" },
  "recovery": { "kdf": "hkdf-sha256", "salt": "…", "nonce": "…", "ciphertext": "…" }
}
```

- Each wrapped blob's AEAD associated data is `syncmyenv/keyfile/v1/<method>/<recipient>`,
  so blobs can't be swapped between methods or vaults, and the recipient can't be replaced.
- Argon2 params are stored per file (upgradeable) with a floor, so a tampered file can't
  downgrade them.
- Written atomically (temp + fsync + rename). `init` refuses to overwrite an existing vault.
- Safe to sync to remotes: it holds no plaintext secret. New devices fetch it and unlock
  with the password or recovery key.

### Recovery key

`SME1-XXXX-…` — 240 random bits + 16-bit checksum, Crockford base32 (no I/L/O/U;
look-alikes accepted when typing). Shown once at `init`. Typos are caught by the checksum
before an unlock attempt.

## Local vault (`~/.syncmyenv/`, dir 0700, files 0600)

| File | Contents |
|---|---|
| `keys.json` | wrapped vault key (see above) — safe to sync |
| `vault.db` | SQLite: `files`, `revisions` |
| `change.key` | device-local HMAC key for change detection — never synced |

| Table | Columns |
|---|---|
| `files` | id, **path (plaintext, local only)**, project, protected_at, removed_at |
| `revisions` | file_id, seq, change_mac, size, **sealed** (age ciphertext), source (`protect`/`snapshot`/`restore`), device, created_at |

Design decisions:

- **Contents are always sealed**, even locally. A stolen `vault.db` reveals no secret values.
- **Paths are plaintext locally.** The daemon must know what to watch *without* your password,
  and the files themselves live on this same disk. Anything sent to a remote seals paths too.
- **Change detection** uses `HMAC(change.key, content)`. The daemon can't use the vault key
  (it doesn't have it). The change key only guards against someone who can already read the
  plaintext `.env` files on this disk, so it adds no exposure. It never leaves the device.
- Revisions are **full sealed snapshots** (env files are tiny) — no diffs, no chains to break.
- **Restore never loses data**: current on-disk content is snapshotted first if it isn't
  already in history; the restore itself is recorded as a new revision. Writes are atomic
  (temp + rename) and keep the file's mode (new files get 0600).
- **Unprotect keeps history**; re-protecting continues it.
- Skipped: symlinks, non-regular files, files > 1 MiB.

## Daemon (`sme daemon`)

```text
fsnotify (parent dirs) ─▶ filter: protected path? ─▶ debounce 500ms ─▶ SnapshotPaths
       ▲                                                                  │
       └── reload every 10s (new/unprotected files, dirs that reappeared)  ▼
           reconcile every 5m + on event overflow ─────────────▶ Snapshot(all)
```

- Watches **parent directories**, not files: editors save via temp file + rename, which
  drops file-level watches. Events are filtered to protected paths only.
- **Debounce**: a burst of saves becomes one revision with the final content.
- **Startup snapshot** catches edits made while the daemon was stopped.
- **Reload** picks up files protected/unprotected by the CLI while it runs, and re-adds
  watches for directories that were deleted and came back (e.g. re-cloned repos).
- **Reconcile** every 5 minutes (and on inotify overflow) — belt and braces for missed events
  (sleep/wake, network filesystems).
- Needs **no password**: sealing uses the public recipient; change detection the device key.
- **Single instance**: `~/.syncmyenv/daemon.lock` (flock, released by the OS on crash).
- `sme daemon install` → launchd agent (`~/Library/LaunchAgents/com.syncmyenv.daemon.plist`)
  or systemd user unit (`~/.config/systemd/user/syncmyenv.service`). Logs to
  `~/.syncmyenv/daemon.log` on macOS, `journalctl --user -u syncmyenv` on Linux.

## Restore on a new machine

Paths are stored relative to scan roots plus a project identity (git remote URL). On restore,
SyncMyEnv maps projects to wherever they live on the new machine.

## Conflicts

`.env` files are key/value, so do a per-key 3-way merge against the common ancestor revision.
Only prompt when both sides changed the same key. Never show values by default.

## Sharing

Share links carry the decryption key in the URL fragment (`/s/<id>#<key>`), which
browsers never send to the server.

## Phases

1. Local: scan, vault, watcher, history, restore (+ `folder` storage backend)
2. Sync: server, auth, multi-device, conflicts
3. Recovery: new-device setup, selective restore, backup verification
4. Sharing: expiring, read-only, per-variable, revocable
5. Desktop UI
