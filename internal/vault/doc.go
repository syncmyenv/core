// Package vault owns the local SQLite vault (~/.syncmyenv/vault.db):
// projects, files, revisions, sync_queue, devices, settings.
//
// Revisions are full encrypted snapshots (env files are tiny). Paths and
// project names are stored encrypted; dedup uses HMAC(vault key, content).
// See docs/architecture.md.
package vault
