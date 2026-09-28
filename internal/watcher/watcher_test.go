package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/vault"
)

func TestMain(m *testing.M) {
	crypto.DefaultArgon = crypto.ArgonParams{Memory: 8 * 1024, Time: 1, Threads: 1}
	os.Exit(m.Run())
}

type harness struct {
	t      *testing.T
	v      *vault.Vault
	events chan vault.SnapshotResult
	dir    string
}

func start(t *testing.T, beforeRun func(h *harness)) *harness {
	t.Helper()
	t.Setenv(config.HomeEnv, filepath.Join(t.TempDir(), "home"))
	k, _ := crypto.NewVaultKey()
	rk, _ := crypto.NewRecoveryKey()
	kf, _ := crypto.NewKeyFile(k, "correct horse battery", rk)
	if err := vault.CreateKeyFile(kf); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Resolve symlinks (macOS: /var → /private/var) — the vault stores resolved paths.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, v: v, events: make(chan vault.SnapshotResult, 100), dir: dir}
	if beforeRun != nil {
		beforeRun(h)
	}
	w, err := New(v, Options{
		Debounce:   80 * time.Millisecond,
		Reload:     100 * time.Millisecond,
		Reconcile:  time.Hour,
		OnSnapshot: func(r vault.SnapshotResult) { h.events <- r },
		OnError:    func(err error) { t.Logf("watcher error: %v", err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; v.Close() })
	time.Sleep(150 * time.Millisecond) // let initial watches settle
	return h
}

func (h *harness) write(name, content string) string {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) protect(p string) {
	h.t.Helper()
	if _, err := h.v.Protect(context.Background(), []string{p}); err != nil {
		h.t.Fatal(err)
	}
}

// expect waits for a snapshot of path with the given seq.
func (h *harness) expect(path string, seq int) {
	h.t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case r := <-h.events:
			if r.Path == path && r.Seq == seq {
				return
			}
			if r.Path == path && r.Seq > seq {
				h.t.Fatalf("%s: got rev %d, wanted %d (too many revisions)", filepath.Base(path), r.Seq, seq)
			}
		case <-deadline:
			h.t.Fatalf("timed out waiting for %s rev %d", filepath.Base(path), seq)
		}
	}
}

// quiet asserts no snapshot happens for a while.
func (h *harness) quiet(d time.Duration) {
	h.t.Helper()
	select {
	case r := <-h.events:
		h.t.Fatalf("unexpected snapshot: %+v", r)
	case <-time.After(d):
	}
}

func TestEditsBecomeRevisions(t *testing.T) {
	var env string
	h := start(t, func(h *harness) {
		env = h.write(".env", "A=1\n")
		h.protect(env)
	})

	// plain write
	h.write(".env", "A=2\n")
	h.expect(env, 2)

	// burst of saves → one revision after the debounce
	for i := range 10 {
		h.write(".env", "A=burst"+string(rune('0'+i))+"\n")
		time.Sleep(10 * time.Millisecond)
	}
	h.expect(env, 3)
	h.quiet(300 * time.Millisecond)

	// editor-style atomic save: write temp file, rename over the original
	tmp := h.write(".env.swp", "A=atomic\n")
	if err := os.Rename(tmp, env); err != nil {
		t.Fatal(err)
	}
	h.expect(env, 4)

	// saving identical content creates nothing
	h.write(".env", "A=atomic\n")
	h.quiet(300 * time.Millisecond)

	// unrelated files in the same directory are ignored
	h.write(".env.example", "A=\n")
	h.write("README.md", "hi\n")
	h.quiet(300 * time.Millisecond)

	// delete then recreate
	os.Remove(env)
	time.Sleep(150 * time.Millisecond)
	h.write(".env", "A=recreated\n")
	h.expect(env, 5)
}

func TestPicksUpNewlyProtectedFiles(t *testing.T) {
	h := start(t, nil)
	sub := filepath.Join(h.dir, "api")
	os.MkdirAll(sub, 0o755)
	env := filepath.Join(sub, ".env")
	os.WriteFile(env, []byte("X=1\n"), 0o600)

	// protected by another process (the CLI) while the daemon runs
	other, err := vault.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Protect(context.Background(), []string{env}); err != nil {
		t.Fatal(err)
	}
	other.Close()

	time.Sleep(300 * time.Millisecond) // > reload interval
	os.WriteFile(env, []byte("X=2\n"), 0o600)
	h.expect(env, 2)

	// unprotected → no longer versioned
	if err := h.v.Unprotect(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	os.WriteFile(env, []byte("X=3\n"), 0o600)
	h.quiet(400 * time.Millisecond)
}

func TestCatchesChangesMadeWhileStopped(t *testing.T) {
	var env string
	h := start(t, func(h *harness) {
		env = h.write(".env", "A=1\n")
		h.protect(env)
		h.write(".env", "A=edited while daemon was off\n")
	})
	h.expect(env, 2)
}
