# Architecture

## Principles

- **Local is the source of truth.** Remote storage is backup, sync and recovery.
- **Only ciphertext leaves the machine** — including paths and project names.
- **Automatic.** After setup, the daemon versions and syncs without prompts.

## Key hierarchy

```text
master password ──Argon2id──► KEK₁ ─┐
                                    ├─ wraps ─► vault identity (X25519 private key)
recovery key (printed at init) ──► KEK₂ ─┘
                                              │
                               vault recipient (public key)
                                              │
               daemon encrypts each revision to the public key (age)
```

- The daemon only needs the **public** key → runs unattended, can't read old secrets.
- `history --show`, `restore`, `share` unlock the identity (password, or OS keychain session).
- New devices get the wrapped identity from remote and unlock it with the password or recovery key.
- Content dedup/change detection: `HMAC-SHA256(vault_mac_key, plaintext)` — never a bare hash.

## Local vault (`~/.syncmyenv/vault.db`)

| Table | Purpose |
|---|---|
| `projects` | id, encrypted name, identity hint (git remote URL, encrypted) |
| `files` | id, project_id, encrypted path relative to scan root, root id, protected flag |
| `revisions` | id, file_id, seq, content MAC, blob id, created_at, device_id |
| `sync_queue` | pending uploads/downloads |
| `devices` | device id, name, public key |
| `settings` | scan roots, excludes, remote config |

Revisions are full encrypted snapshots (env files are small).

## Watching

Editors save via temp-file + rename, which drops file-level watches. Watch **parent
directories**, filter by protected file names, debounce ~500ms, then MAC → compare →
new revision if changed.

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
