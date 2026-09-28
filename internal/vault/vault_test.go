package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
)

func TestMain(m *testing.M) {
	crypto.DefaultArgon = crypto.ArgonParams{Memory: 8 * 1024, Time: 1, Threads: 1}
	os.Exit(m.Run())
}

func setup(t *testing.T) (*Vault, *crypto.VaultKey, string) {
	t.Helper()
	t.Setenv(config.HomeEnv, filepath.Join(t.TempDir(), "home"))
	k, _ := crypto.NewVaultKey()
	rk, _ := crypto.NewRecoveryKey()
	kf, err := crypto.NewKeyFile(k, "correct horse battery", rk)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(kf); err != nil {
		t.Fatal(err)
	}
	v, err := Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, k, t.TempDir()
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProtectSnapshotRestore(t *testing.T) {
	ctx := context.Background()
	v, key, dir := setup(t)
	env := filepath.Join(dir, ".env")
	write(t, env, "DB=v1\n")

	res, err := v.Protect(ctx, []string{env})
	if err != nil || len(res) != 1 || !res[0].Added {
		t.Fatalf("protect: %v %+v", err, res)
	}
	// protecting again is idempotent
	res, _ = v.Protect(ctx, []string{env})
	if res[0].Added {
		t.Fatal("re-protect should not add")
	}

	// unchanged → no new revision
	snap, _ := v.Snapshot(ctx)
	if snap[0].Seq != 0 {
		t.Fatalf("unchanged file got rev %d", snap[0].Seq)
	}
	write(t, env, "DB=v2\n")
	snap, _ = v.Snapshot(ctx)
	if snap[0].Seq != 2 {
		t.Fatalf("changed file: want rev 2, got %d", snap[0].Seq)
	}

	// oops: overwritten with garbage → restore rev 1; garbage is saved first
	write(t, env, "OOPS\n")
	r, err := v.Restore(ctx, key, env, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.SavedSeq != 3 || r.NewSeq != 4 {
		t.Fatalf("restore bookkeeping: %+v", r)
	}
	if b, _ := os.ReadFile(env); string(b) != "DB=v1\n" {
		t.Fatalf("restored content %q", b)
	}
	revs, _ := v.History(ctx, env)
	if len(revs) != 4 || revs[0].Source != "restore" || revs[1].Size != len("OOPS\n") {
		t.Fatalf("history: %+v", revs)
	}
	// the "oops" content is still recoverable
	if _, err := v.Restore(ctx, key, env, 3, filepath.Join(dir, "oops.env")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "oops.env")); string(b) != "OOPS\n" {
		t.Fatalf("--to content %q", b)
	}

	// restoring what's already there is a no-op
	r, _ = v.Restore(ctx, key, env, 0, "")
	if !r.Unchanged {
		t.Fatalf("expected unchanged, got %+v", r)
	}
}

func TestRestoreMissingKeepsMode(t *testing.T) {
	ctx := context.Background()
	v, key, dir := setup(t)
	env := filepath.Join(dir, "app", ".env.local")
	os.MkdirAll(filepath.Dir(env), 0o755)
	write(t, env, "A=1\n")
	v.Protect(ctx, []string{env})
	os.RemoveAll(filepath.Dir(env))

	m, _ := v.Missing(ctx)
	if len(m) != 1 {
		t.Fatalf("missing: %d", len(m))
	}
	if _, err := v.Restore(ctx, key, env, 0, ""); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(env)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("restored file mode %v", st.Mode().Perm())
	}
}

func TestSealedAtRest(t *testing.T) {
	ctx := context.Background()
	v, _, dir := setup(t)
	env := filepath.Join(dir, ".env")
	write(t, env, "STRIPE_SECRET=sk_live_supersecret\n")
	v.Protect(ctx, []string{env})
	v.Close()

	home, _ := config.Home()
	for _, f := range []string{"vault.db", "vault.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(home, f))
		if bytes.Contains(b, []byte("sk_live_supersecret")) {
			t.Fatalf("%s contains plaintext secret", f)
		}
	}
	if st, _ := os.Stat(filepath.Join(home, "vault.db")); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("vault.db mode %v", st.Mode().Perm())
	}
}

func TestWrongKeyCannotRestore(t *testing.T) {
	ctx := context.Background()
	v, _, dir := setup(t)
	env := filepath.Join(dir, ".env")
	write(t, env, "A=1\n")
	v.Protect(ctx, []string{env})
	other, _ := crypto.NewVaultKey()
	if _, err := v.Restore(ctx, other, env, 0, filepath.Join(dir, "x")); err == nil {
		t.Fatal("restored with the wrong vault key")
	}
}

func TestUnprotectKeepsHistory(t *testing.T) {
	ctx := context.Background()
	v, key, dir := setup(t)
	env := filepath.Join(dir, ".env")
	write(t, env, "A=1\n")
	v.Protect(ctx, []string{env})
	if err := v.Unprotect(ctx, env); err != nil {
		t.Fatal(err)
	}
	if fs, _ := v.List(ctx); len(fs) != 0 {
		t.Fatal("unprotected file still listed")
	}
	if snap, _ := v.Snapshot(ctx); len(snap) != 0 {
		t.Fatal("unprotected file still snapshotted")
	}
	if revs, err := v.History(ctx, env); err != nil || len(revs) != 1 {
		t.Fatalf("history after unprotect: %v %d", err, len(revs))
	}
	if _, err := v.Restore(ctx, key, env, 1, filepath.Join(dir, "back")); err != nil {
		t.Fatalf("restore after unprotect: %v", err)
	}
	if err := v.Unprotect(ctx, filepath.Join(dir, "nope")); !errors.Is(err, ErrNotProtected) {
		t.Fatalf("want ErrNotProtected, got %v", err)
	}
	// re-protecting brings it back with continuous history
	res, _ := v.Protect(ctx, []string{env})
	if !res[0].Added {
		t.Fatal("re-protect after unprotect should add")
	}
}

func TestSkipsNonRegularAndHuge(t *testing.T) {
	ctx := context.Background()
	v, _, dir := setup(t)
	big := filepath.Join(dir, ".env.big")
	os.WriteFile(big, make([]byte, crypto.MaxPlaintext+1), 0o600)
	link := filepath.Join(dir, ".env.link")
	os.Symlink(big, link)
	res, err := v.Protect(ctx, []string{big, link, dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Skipped == "" {
			t.Fatalf("%s should be skipped", r.Path)
		}
	}
}

func TestCleanPathResolvesMissingDirs(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	realResolved, _ := filepath.EvalSymlinks(real)
	cases := map[string]string{
		filepath.Join(link, ".env"):                    filepath.Join(realResolved, ".env"),
		filepath.Join(link, "gone", "deeper", ".env"):  filepath.Join(realResolved, "gone", "deeper", ".env"),
		filepath.Join(link, "gone", "..", "x", ".env"): filepath.Join(realResolved, "x", ".env"),
	}
	for in, want := range cases {
		got, err := CleanPath(in)
		if err != nil || got != want {
			t.Errorf("CleanPath(%s) = %s, want %s", in, got, want)
		}
	}
}
