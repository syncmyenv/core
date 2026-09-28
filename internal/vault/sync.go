package vault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/scanner"
	"github.com/syncmyenv/core/protocol"
)

// PendingRevision is a local revision not yet pushed to the server.
type PendingRevision struct {
	RevisionID string
	Path       string
	Project    string
	Seq        int
	Size       int
	Source     string
	Device     string
	CreatedAt  int64
	Sealed     []byte
}

// Pending lists revisions created on this device that haven't been pushed.
func (v *Vault) Pending(ctx context.Context, limit int) ([]PendingRevision, error) {
	rows, err := v.db.QueryContext(ctx, `SELECT r.id, f.path, f.project, r.seq, r.size, r.source, r.device, r.created_at, r.sealed
		FROM revisions r JOIN files f ON f.id = r.file_id
		WHERE r.pushed_at IS NULL AND r.origin = 'local' ORDER BY r.created_at, r.seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingRevision
	for rows.Next() {
		var p PendingRevision
		if err := rows.Scan(&p.RevisionID, &p.Path, &p.Project, &p.Seq, &p.Size, &p.Source, &p.Device, &p.CreatedAt, &p.Sealed); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountPending returns how many local revisions await pushing.
func (v *Vault) CountPending(ctx context.Context) (int, error) {
	var n int
	err := v.db.QueryRowContext(ctx, `SELECT count(*) FROM revisions WHERE pushed_at IS NULL AND origin = 'local'`).Scan(&n)
	return n, err
}

// MarkPushed records that revisions reached the server.
func (v *Vault) MarkPushed(ctx context.Context, revisionIDs, objectIDs []string) error {
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := v.now().Unix()
	for i, id := range revisionIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE revisions SET pushed_at = ?, object_id = ? WHERE id = ?`, now, objectIDs[i], id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// State reads a sync_state value ("" if unset).
func (v *Vault) State(ctx context.Context, key string) (string, error) {
	var s string
	err := v.db.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key = ?`, key).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return s, err
}

// SetState writes a sync_state value.
func (v *Vault) SetState(ctx context.Context, key, value string) error {
	_, err := v.db.ExecContext(ctx, `INSERT INTO sync_state (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// NextDeviceSeq atomically reserves n device sequence numbers, returning the first.
func (v *Vault) NextDeviceSeq(ctx context.Context, n int) (int64, error) {
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur string
	err = tx.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key = 'device_seq'`).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	last, _ := strconv.ParseInt(cur, 10, 64)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sync_state (key, value) VALUES ('device_seq', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, strconv.FormatInt(last+int64(n), 10)); err != nil {
		return 0, err
	}
	return last + 1, tx.Commit()
}

// ImportResult says what happened to a remote revision.
type ImportResult struct {
	Path      string
	Seq       int  // local seq assigned (0 = already had it)
	Applied   bool // written to disk (fast-forward)
	Conflict  bool // disk had local, unsnapshotted edits; kept them, remote is in history
	OnlyStore bool // file missing on disk: stored in history (sme restore --missing)
}

// ImportRemote adds a revision that came from another device. key is needed to
// compute the change MAC (and to write the content to disk on fast-forward).
//
// Fast-forward rule: if the file on disk still equals this device's latest
// known revision (no local edits since), the remote content is written to
// disk. Otherwise disk wins for now and the remote revision is kept in
// history — nothing is ever lost.
func (v *Vault) ImportRemote(ctx context.Context, key *crypto.VaultKey, p protocol.EntryPayload, originDevice, objectID string, sealed []byte) (*ImportResult, error) {
	if !SafeImportPath(p.Path) {
		return nil, fmt.Errorf("refusing unsafe path %q", p.Path)
	}
	abs := FromPortable(p.Path)
	res := &ImportResult{Path: abs}
	plain, err := key.Open(sealed)
	if err != nil {
		return nil, err
	}

	f, err := v.fileByPath(ctx, abs)
	fileID := ""
	switch {
	case errors.Is(err, sql.ErrNoRows):
		fileID = newID()
		project := p.Project
		if project == "" {
			project = scanner.ProjectOf(abs)
		}
		if _, err := v.db.ExecContext(ctx, `INSERT INTO files (id, path, project, protected_at) VALUES (?, ?, ?, ?)`,
			fileID, abs, project, v.now().Unix()); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		fileID = f.id
	}

	var n int
	if err := v.db.QueryRowContext(ctx, `SELECT count(*) FROM revisions WHERE file_id = ? AND object_id = ?`, fileID, objectID).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return res, nil // already imported
	}

	var lastSeq int
	var lastMAC []byte
	err = v.db.QueryRowContext(ctx, `SELECT seq, change_mac FROM revisions WHERE file_id = ? ORDER BY seq DESC LIMIT 1`, fileID).Scan(&lastSeq, &lastMAC)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	mac := changeMAC(v.changeKey, plain)
	now := v.now().Unix()
	_, err = v.db.ExecContext(ctx, `INSERT INTO revisions (id, file_id, seq, change_mac, size, sealed, source, device, created_at, object_id, pushed_at, origin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, newID(), fileID, lastSeq+1, mac, len(plain), sealed, p.Source, p.Device, p.CreatedAt, objectID, now, originDevice)
	if err != nil {
		return nil, err
	}
	res.Seq = lastSeq + 1

	disk, err := readEnvFile(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.OnlyStore = true
	case err != nil:
		return nil, err
	case bytes.Equal(changeMAC(v.changeKey, disk), mac):
		// already identical
	case lastMAC != nil && bytes.Equal(changeMAC(v.changeKey, disk), lastMAC):
		if err := writeFileAtomic(abs, plain); err != nil {
			return nil, err
		}
		res.Applied = true
	default:
		res.Conflict = true
	}
	return res, nil
}

// ToPortable turns an absolute path into "~/…" when it's under the home
// directory, so it maps onto other machines with different usernames.
func ToPortable(abs string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(abs, home+string(filepath.Separator)) {
		return "~/" + filepath.ToSlash(abs[len(home)+1:])
	}
	return filepath.ToSlash(abs)
}

// SafeImportPath limits what a remote entry may name: a home-relative or
// absolute path, no ".." tricks, and an env-file name (.env, .env.*, env,
// env.*). Even a legitimate-but-compromised device can't make `restore`
// write ~/.bashrc or ~/.ssh/authorized_keys.
func SafeImportPath(p string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	if !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	base := p[strings.LastIndex(p, "/")+1:]
	return scanner.IsEnvFile(base) && !scanner.IsTemplate(base)
}

// FromPortable is the inverse of ToPortable on this machine.
func FromPortable(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, filepath.FromSlash(p[2:]))
		}
	}
	return filepath.Clean(filepath.FromSlash(p))
}
