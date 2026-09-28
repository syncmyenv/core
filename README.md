# SyncMyEnv — core

Local agent and CLI (`syncmyenv` / `sme`) for SyncMyEnv: discovery, encrypted vault,
file watcher, version history, restore and sync.

> Local-first, encrypted, automatic, recoverable.

## Quick start

```bash
go mod tidy          # first time only
make build           # -> bin/syncmyenv (+ bin/sme symlink)
./bin/sme init                       # create vault, prints your recovery key
./bin/sme status
./bin/sme scan ~/Projects ~/Work
```

## Status

| Command | Status |
|---|---|
| `scan` | ✅ works — discovers `.env`, `.env.*`, `env`, `env.*`; skips templates, `node_modules`, `.git`, etc. |
| `init` | ✅ post-quantum vault key, wrapped by master password + recovery key |
| `status` | ✅ vault info (files/sync come with `protect`) |
| `keys verify`, `keys passwd` | ✅ check password/recovery key, change password (or reset via recovery key) |
| `protect`, `list`, `history`, `restore`, `daemon` | Phase 1 — next |
| `sync` | Phase 2 |
| `share` | Phase 4 |

## Layout

```text
cmd/syncmyenv/      entrypoint
internal/cli/       cobra commands
internal/scanner/   env file discovery
internal/config/    paths (~/.syncmyenv, SYNCMYENV_HOME)
internal/crypto/    key hierarchy (Argon2id + age/X25519)
internal/vault/     SQLite vault
internal/watcher/   fsnotify watcher (parent-dir watches, debounce)
internal/storage/   remote backend interface (folder, S3/R2, server)
docs/               architecture notes
```

See [docs/architecture.md](docs/architecture.md).
