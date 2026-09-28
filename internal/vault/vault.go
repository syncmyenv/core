package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/scanner"
)

var (
	ErrNotProtected = errors.New("file is not protected — run `sme protect` first")
	ErrNoRevision   = errors.New("no such revision")
)

// Vault is an open local vault. It can protect, snapshot and list without the
// master password; reading contents (Restore) needs an unlocked VaultKey.
type Vault struct {
	db        *sql.DB
	keys      *crypto.KeyFile
	changeKey []byte
	device    string
	now       func() time.Time
}

// Open opens the vault for the current SYNCMYENV_HOME. Requires `sme init`.
func Open(ctx context.Context) (*Vault, error) {
	kf, err := LoadKeyFile()
	if err != nil {
		return nil, err
	}
	ck, err := loadChangeKey()
	if err != nil {
		return nil, err
	}
	db, err := openDB(ctx)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &Vault{db: db, keys: kf, changeKey: ck, device: host, now: time.Now}, nil
}

func (v *Vault) Close() error { return v.db.Close() }

// KeyFile returns the vault's (wrapped) key file.
func (v *Vault) KeyFile() *crypto.KeyFile { return v.keys }

// File is a protected (or formerly protected) env file.
type File struct {
	ID          string
	Path        string
	Project     string
	ProtectedAt time.Time
	Revisions   int
	LastChange  time.Time
	Size        int
}

// Revision is one sealed version of a file. Contents need the vault key.
type Revision struct {
	Seq       int
	Size      int
	Source    string
	Device    string
	CreatedAt time.Time
	sealed    []byte
	mac       []byte
}

// ProtectResult says what Protect did for one path.
type ProtectResult struct {
	Path    string
	Added   bool // newly protected (false = already protected)
	Skipped string
}

// Protect starts protecting files and seals their current contents as revision 1.
func (v *Vault) Protect(ctx context.Context, paths []string) ([]ProtectResult, error) {
	out := make([]ProtectResult, 0, len(paths))
	for _, p := range paths {
		abs, err := CleanPath(p)
		if err != nil {
			return out, err
		}
		res := ProtectResult{Path: abs}
		data, err := readEnvFile(abs)
		if err != nil {
			res.Skipped = err.Error()
			out = append(out, res)
			continue
		}
		existing, err := v.fileByPath(ctx, abs)
		switch {
		case err == nil && existing.removedAt.Valid:
			if _, err := v.db.ExecContext(ctx, `UPDATE files SET removed_at = NULL WHERE id = ?`, existing.id); err != nil {
				return out, err
			}
			res.Added = true
			if _, err := v.snapshotFile(ctx, existing.id, data, "protect"); err != nil {
				return out, err
			}
		case err == nil:
			// already protected; just make sure the latest content is captured
			if _, err := v.snapshotFile(ctx, existing.id, data, "snapshot"); err != nil {
				return out, err
			}
		case errors.Is(err, sql.ErrNoRows):
			id := newID()
			if _, err := v.db.ExecContext(ctx, `INSERT INTO files (id, path, project, protected_at) VALUES (?, ?, ?, ?)`,
				id, abs, scanner.ProjectOf(abs), v.now().Unix()); err != nil {
				return out, err
			}
			if _, err := v.snapshotFile(ctx, id, data, "protect"); err != nil {
				return out, err
			}
			res.Added = true
		default:
			return out, err
		}
		out = append(out, res)
	}
	return out, nil
}

// Unprotect stops watching a file. Its history is kept (and restorable).
func (v *Vault) Unprotect(ctx context.Context, path string) error {
	f, err := v.activeFile(ctx, path)
	if err != nil {
		return err
	}
	_, err = v.db.ExecContext(ctx, `UPDATE files SET removed_at = ? WHERE id = ?`, v.now().Unix(), f.id)
	return err
}

// SnapshotResult reports what a snapshot found for one file.
type SnapshotResult struct {
	Path    string
	Seq     int    // new revision number, 0 if unchanged
	Missing bool   // file no longer exists on disk
	Error   string // unreadable, too large…
}

// Snapshot seals a new revision for every protected file whose content
// changed. Needs no password: it only uses the public recipient.
func (v *Vault) Snapshot(ctx context.Context) ([]SnapshotResult, error) {
	return v.SnapshotPaths(ctx, nil)
}

// SnapshotPaths is Snapshot limited to the given absolute paths (nil = all).
// Paths that aren't protected are ignored.
func (v *Vault) SnapshotPaths(ctx context.Context, only []string) ([]SnapshotResult, error) {
	files, err := v.List(ctx)
	if err != nil {
		return nil, err
	}
	var want map[string]bool
	if only != nil {
		want = make(map[string]bool, len(only))
		for _, p := range only {
			want[p] = true
		}
	}
	out := make([]SnapshotResult, 0, len(files))
	for _, f := range files {
		if want != nil && !want[f.Path] {
			continue
		}
		r := SnapshotResult{Path: f.Path}
		data, err := readEnvFile(f.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			r.Missing = true
		case err != nil:
			r.Error = err.Error()
		default:
			seq, err := v.snapshotFile(ctx, f.ID, data, "snapshot")
			if err != nil {
				return out, err
			}
			r.Seq = seq
		}
		out = append(out, r)
	}
	return out, nil
}

// snapshotFile adds a revision if data differs from the latest one.
// Returns the new seq, or 0 if unchanged.
func (v *Vault) snapshotFile(ctx context.Context, fileID string, data []byte, source string) (int, error) {
	mac := changeMAC(v.changeKey, data)
	var lastSeq int
	var lastMAC []byte
	err := v.db.QueryRowContext(ctx, `SELECT seq, change_mac FROM revisions WHERE file_id = ? ORDER BY seq DESC LIMIT 1`, fileID).
		Scan(&lastSeq, &lastMAC)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if lastMAC != nil && bytes.Equal(lastMAC, mac) {
		return 0, nil
	}
	sealed, err := crypto.Seal(v.keys.Recipient, data)
	if err != nil {
		return 0, err
	}
	return v.insertRevision(ctx, fileID, lastSeq+1, mac, len(data), sealed, source)
}

func (v *Vault) insertRevision(ctx context.Context, fileID string, seq int, mac []byte, size int, sealed []byte, source string) (int, error) {
	_, err := v.db.ExecContext(ctx, `INSERT INTO revisions (id, file_id, seq, change_mac, size, sealed, source, device, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, newID(), fileID, seq, mac, size, sealed, source, v.device, v.now().Unix())
	return seq, err
}

// List returns protected files (not unprotected ones).
func (v *Vault) List(ctx context.Context) ([]File, error) {
	rows, err := v.db.QueryContext(ctx, `
		SELECT f.id, f.path, f.project, f.protected_at, count(r.id), coalesce(max(r.created_at), 0),
		       coalesce((SELECT size FROM revisions WHERE file_id = f.id ORDER BY seq DESC LIMIT 1), 0)
		FROM files f LEFT JOIN revisions r ON r.file_id = f.id
		WHERE f.removed_at IS NULL
		GROUP BY f.id ORDER BY f.project, f.path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var prot, last int64
		if err := rows.Scan(&f.ID, &f.Path, &f.Project, &prot, &f.Revisions, &last, &f.Size); err != nil {
			return nil, err
		}
		f.ProtectedAt, f.LastChange = time.Unix(prot, 0), time.Unix(last, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

// History lists revisions of a file, newest first. Works for unprotected files too.
func (v *Vault) History(ctx context.Context, path string) ([]Revision, error) {
	f, err := v.anyFile(ctx, path)
	if err != nil {
		return nil, err
	}
	return v.revisions(ctx, f.id)
}

func (v *Vault) revisions(ctx context.Context, fileID string) ([]Revision, error) {
	rows, err := v.db.QueryContext(ctx, `SELECT seq, size, source, device, created_at, sealed, change_mac
		FROM revisions WHERE file_id = ? ORDER BY seq DESC`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var r Revision
		var ts int64
		if err := rows.Scan(&r.Seq, &r.Size, &r.Source, &r.Device, &ts, &r.sealed, &r.mac); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RestoreResult describes a restore.
type RestoreResult struct {
	Path      string
	FromSeq   int // revision that was restored
	SavedSeq  int // revision capturing the overwritten content (0 if none/unchanged)
	NewSeq    int // revision recording the restore
	Unchanged bool
}

// Restore writes revision seq (0 = latest) back to disk, or to `to` if set.
// The current on-disk content is snapshotted first, so a restore never loses data.
func (v *Vault) Restore(ctx context.Context, key *crypto.VaultKey, path string, seq int, to string) (*RestoreResult, error) {
	f, err := v.anyFile(ctx, path)
	if err != nil {
		return nil, err
	}
	revs, err := v.revisions(ctx, f.id)
	if err != nil {
		return nil, err
	}
	var rev *Revision
	for i := range revs {
		if seq == 0 || revs[i].Seq == seq {
			rev = &revs[i]
			break
		}
	}
	if rev == nil {
		return nil, fmt.Errorf("%w %d for %s", ErrNoRevision, seq, f.path)
	}
	plain, err := key.Open(rev.sealed)
	if err != nil {
		return nil, err
	}
	res := &RestoreResult{Path: f.path, FromSeq: rev.Seq}
	dest := f.path
	if to != "" {
		if dest, err = CleanPath(to); err != nil {
			return nil, err
		}
		res.Path = dest
		return res, writeFileAtomic(dest, plain)
	}

	// Save whatever is on disk now before overwriting it.
	if cur, err := readEnvFile(dest); err == nil {
		if bytes.Equal(cur, plain) {
			res.Unchanged = true
			return res, nil
		}
		if res.SavedSeq, err = v.snapshotFile(ctx, f.id, cur, "snapshot"); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := writeFileAtomic(dest, plain); err != nil {
		return nil, err
	}
	last := revs[0].Seq
	if res.SavedSeq > last {
		last = res.SavedSeq
	}
	// Record the restore as a new revision (reusing the sealed blob).
	res.NewSeq, err = v.insertRevision(ctx, f.id, last+1, rev.mac, rev.Size, rev.sealed, "restore")
	return res, err
}

// Missing returns protected files that don't exist on disk (e.g. new machine, deleted).
func (v *Vault) Missing(ctx context.Context) ([]File, error) {
	files, err := v.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []File
	for _, f := range files {
		if _, err := os.Stat(f.Path); errors.Is(err, fs.ErrNotExist) {
			out = append(out, f)
		}
	}
	return out, nil
}

// ---- helpers ----

type fileRow struct {
	id, path  string
	removedAt sql.NullInt64
}

func (v *Vault) fileByPath(ctx context.Context, abs string) (*fileRow, error) {
	var f fileRow
	err := v.db.QueryRowContext(ctx, `SELECT id, path, removed_at FROM files WHERE path = ?`, abs).Scan(&f.id, &f.path, &f.removedAt)
	return &f, err
}

func (v *Vault) anyFile(ctx context.Context, path string) (*fileRow, error) {
	abs, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	f, err := v.fileByPath(ctx, abs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w", abs, ErrNotProtected)
	}
	return f, err
}

func (v *Vault) activeFile(ctx context.Context, path string) (*fileRow, error) {
	f, err := v.anyFile(ctx, path)
	if err != nil {
		return nil, err
	}
	if f.removedAt.Valid {
		return nil, fmt.Errorf("%s: %w", f.path, ErrNotProtected)
	}
	return f, nil
}

// CleanPath makes a path absolute and clean, with symlinks in its directories
// resolved — even when some of those directories don't exist (yet, or any
// more): the deepest existing ancestor is resolved and the rest re-appended.
// So "/var/x/app/.env" and "/private/var/x/app/.env" (macOS) are the same
// file whether or not app/ still exists. The file itself is never resolved:
// a symlinked .env is not followed.
func CleanPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	dir, rest := filepath.Dir(abs), []string{filepath.Base(abs)}
	for {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, rest[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, nil
		}
		rest = append(rest, filepath.Base(dir))
		dir = parent
	}
}

func readEnvFile(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if st.Size() > crypto.MaxPlaintext {
		return nil, crypto.ErrTooLarge
	}
	return os.ReadFile(p)
}

// writeFileAtomic writes via temp + rename, keeping the existing file mode
// (or 0600 for new files — env files are secrets).
func writeFileAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sme-restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
