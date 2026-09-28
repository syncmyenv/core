# SyncMyEnv — core

Local agent and CLI (`syncmyenv` / `sme`) for SyncMyEnv: discovery, encrypted vault,
file watcher, version history, restore and sync.

> Local-first, encrypted, automatic, recoverable.

## Quick start

```bash
go mod tidy          # first time only
make build           # -> bin/syncmyenv (+ bin/sme symlink)
./bin/sme init                       # create vault, prints your recovery key
./bin/sme protect ~/Projects         # scan + choose + seal revision 1
./bin/sme daemon install             # start on login: every save becomes a revision
./bin/sme snapshot                   # or seal changes by hand
./bin/sme history ~/Projects/app/.env
./bin/sme restore ~/Projects/app/.env --version 2
./bin/sme restore --missing          # everything deleted / new machine
./bin/sme login                      # or: sme login env.mycompany.com (self-hosted)
./bin/sme sync                       # push/pull; the daemon pushes automatically
```

## Status

| Command | Status |
|---|---|
| `scan` | ✅ works — discovers `.env`, `.env.*`, `env`, `env.*`; skips templates, `node_modules`, `.git`, etc. |
| `init` | ✅ post-quantum vault key, wrapped by master password + recovery key |
| `status` | ✅ vault, protected files, missing files |
| `protect`, `unprotect`, `list` | ✅ choose files (dir scan asks first), seal contents |
| `snapshot` | ✅ seal a revision for every changed file — no password needed |
| `history`, `restore` | ✅ revisions; restore by version / `--to` / `--missing`, never loses data |
| `keys verify`, `keys passwd` | ✅ check password/recovery key, change password (or reset via recovery key) |
| `daemon`, `daemon install/uninstall` | ✅ watches files, seals every change; launchd / systemd --user |
| `login`, `logout`, `sync` | ✅ Cloud or self-hosted server; signed, verified, end-to-end encrypted — see [docs/sync.md](docs/sync.md) |
| folder / S3 remotes (BYO storage) | paused |
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
internal/remote/    server connection + syncer (push, verify, pull)
protocol/           PUBLIC: sync wire types + HTTP client (imported by the server)
docs/               architecture notes
```

See [docs/architecture.md](docs/architecture.md).
