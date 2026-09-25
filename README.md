# SyncMyEnv — core

Local agent and CLI (`syncmyenv` / `sme`) for SyncMyEnv: discovery, encrypted vault,
file watcher, version history, restore and sync.

> Local-first, encrypted, automatic, recoverable.

## Quick start

```bash
go mod tidy          # first time only
make build           # -> bin/syncmyenv (+ bin/sme symlink)
./bin/syncmyenv scan ~/Projects ~/Work
./bin/syncmyenv scan ~/Projects --json
```

## Status

| Command | Status |
|---|---|
| `scan` | ✅ works — discovers `.env`, `.env.*`, `env`, `env.*`; skips templates, `node_modules`, `.git`, etc. |
| `init`, `protect`, `list`, `status`, `history`, `restore`, `daemon` | Phase 1 (stubs) |
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
