package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
)

func TestMain(m *testing.M) {
	crypto.DefaultArgon = crypto.ArgonParams{Memory: 8 * 1024, Time: 1, Threads: 1}
	os.Exit(m.Run())
}

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	var out bytes.Buffer
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.Execute()
	return out.String(), err
}

var recoveryRe = regexp.MustCompile(`SME1-[0-9A-Z-]+-\s*│\s*│\s+[0-9A-Z-]+`)

func recoveryFrom(t *testing.T, out string) string {
	t.Helper()
	m := recoveryRe.FindString(out)
	if m == "" {
		t.Fatalf("no recovery key in output:\n%s", out)
	}
	return strings.NewReplacer("│", "", " ", "", "\n", "").Replace(m)
}

func TestKeysLifecycle(t *testing.T) {
	home := filepath.Join(t.TempDir(), "sme")
	t.Setenv(config.HomeEnv, home)

	out, err := run(t, "", "status")
	if err != nil || !strings.Contains(out, "not initialized") {
		t.Fatalf("status before init: %v\n%s", err, out)
	}

	if _, err := run(t, "short\n", "init", "--password-stdin"); err == nil {
		t.Fatal("weak password accepted")
	}

	out, err = run(t, "correct horse battery\n", "init", "--password-stdin")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	rkStr := recoveryFrom(t, out)
	if _, err := crypto.ParseRecoveryKey(rkStr); err != nil {
		t.Fatalf("printed recovery key doesn't parse: %q %v", rkStr, err)
	}

	// file permissions: dir 0700, key file 0600
	if st, _ := os.Stat(home); st.Mode().Perm() != 0o700 {
		t.Fatalf("home perms %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(home, "keys.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("keys.json perms %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(filepath.Join(home, "keys.json"))
	if bytes.Contains(raw, []byte("correct horse")) || bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
		t.Fatal("key file contains a plaintext secret")
	}

	// never overwrite an existing vault
	if _, err := run(t, "another password!!\n", "init", "--password-stdin"); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("re-init: %v", err)
	}

	out, _ = run(t, "", "status")
	if !strings.Contains(out, "✓ initialized") || !strings.Contains(out, "password, recovery key") {
		t.Fatalf("status:\n%s", out)
	}

	if out, err := run(t, "correct horse battery\n", "keys", "verify", "--password-stdin"); err != nil || !strings.Contains(out, "✓ unlocks") {
		t.Fatalf("verify: %v %s", err, out)
	}
	if _, err := run(t, "wrong horse battery\n", "keys", "verify", "--password-stdin"); err == nil {
		t.Fatal("wrong password verified")
	}
	if _, err := run(t, strings.ToLower(rkStr)+"\n", "keys", "verify", "--recovery", "--password-stdin"); err != nil {
		t.Fatalf("recovery verify: %v", err)
	}

	// change password with the old one
	if out, err := run(t, "correct horse battery\nnew passphrase here\n", "keys", "passwd", "--password-stdin"); err != nil {
		t.Fatalf("passwd: %v %s", err, out)
	}
	if _, err := run(t, "correct horse battery\n", "keys", "verify", "--password-stdin"); err == nil {
		t.Fatal("old password still works")
	}
	// forgot it → reset via recovery key
	if _, err := run(t, rkStr+"\nthird passphrase here\n", "keys", "passwd", "--recovery", "--password-stdin"); err != nil {
		t.Fatalf("passwd --recovery: %v", err)
	}
	if _, err := run(t, "third passphrase here\n", "keys", "verify", "--password-stdin"); err != nil {
		t.Fatalf("verify after recovery reset: %v", err)
	}
	if _, err := run(t, rkStr+"\n", "keys", "verify", "--recovery", "--password-stdin"); err != nil {
		t.Fatalf("recovery key must survive password changes: %v", err)
	}
}

func TestNoTTYWithoutFlag(t *testing.T) {
	t.Setenv(config.HomeEnv, t.TempDir())
	_, err := run(t, "correct horse battery\n", "init")
	if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("want tty error, got %v", err)
	}
}

func TestProtectHistoryRestore(t *testing.T) {
	t.Setenv(config.HomeEnv, filepath.Join(t.TempDir(), "sme"))
	proj := filepath.Join(t.TempDir(), "spotify")
	os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	os.MkdirAll(filepath.Join(proj, "node_modules", "x"), 0o755)
	env := filepath.Join(proj, ".env")
	os.WriteFile(env, []byte("DB=one\n"), 0o600)
	os.WriteFile(filepath.Join(proj, ".env.local"), []byte("X=1\n"), 0o600)
	os.WriteFile(filepath.Join(proj, ".env.example"), []byte("DB=\n"), 0o600)
	os.WriteFile(filepath.Join(proj, "node_modules", "x", ".env"), []byte("nope\n"), 0o600)

	if _, err := run(t, "", "protect", env); err == nil {
		t.Fatal("protect before init should fail")
	}
	if _, err := run(t, "correct horse battery\n", "init", "--password-stdin"); err != nil {
		t.Fatal(err)
	}

	// directory scan needs confirmation; non-tty without --yes refuses
	if _, err := run(t, "", "protect", proj); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("want --yes error, got %v", err)
	}
	out, err := run(t, "", "protect", proj, "--yes")
	if err != nil || !strings.Contains(out, "2 file(s) protected") || strings.Contains(out, "node_modules") || strings.Contains(out, ".env.example") {
		t.Fatalf("protect dir: %v\n%s", err, out)
	}

	out, _ = run(t, "", "list")
	if !strings.Contains(out, "spotify") || strings.Count(out, "\n") != 3 {
		t.Fatalf("list:\n%s", out)
	}

	os.WriteFile(env, []byte("DB=two\n"), 0o600)
	out, _ = run(t, "", "snapshot")
	if !strings.Contains(out, "→ rev 2") || !strings.Contains(out, "1 changed, 1 unchanged") {
		t.Fatalf("snapshot:\n%s", out)
	}

	out, _ = run(t, "", "history", env)
	if !strings.Contains(out, "protect") || !strings.Contains(out, "snapshot") {
		t.Fatalf("history:\n%s", out)
	}

	os.Remove(env)
	out, _ = run(t, "", "status")
	if !strings.Contains(out, "2 file(s) in 1 project(s) · 3 revision(s)") || !strings.Contains(out, "missing      1 file(s)") {
		t.Fatalf("status:\n%s", out)
	}

	if _, err := run(t, "wrong password!!\n", "restore", "--missing", "--password-stdin"); err == nil {
		t.Fatal("restore with wrong password")
	}
	out, err = run(t, "correct horse battery\n", "restore", "--missing", "--password-stdin")
	if err != nil || !strings.Contains(out, "restored") {
		t.Fatalf("restore --missing: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(env); string(b) != "DB=two\n" {
		t.Fatalf("restored %q", b)
	}

	// on-disk content is already in history (the restore rev), so nothing extra to save
	out, err = run(t, "correct horse battery\n", "restore", env, "--version", "1", "--password-stdin")
	if err != nil || !strings.Contains(out, "from rev 1") || strings.Contains(out, "previous content saved") {
		t.Fatalf("restore v1: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(env); string(b) != "DB=one\n" {
		t.Fatalf("restored v1 %q", b)
	}
}

func TestRestoreSavesUnsnapshottedEdits(t *testing.T) {
	t.Setenv(config.HomeEnv, filepath.Join(t.TempDir(), "sme"))
	env := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(env, []byte("A=1\n"), 0o600)
	run(t, "correct horse battery\n", "init", "--password-stdin")
	run(t, "", "protect", env)
	os.WriteFile(env, []byte("A=edited-but-never-snapshotted\n"), 0o600)
	out, err := run(t, "correct horse battery\n", "restore", env, "--version", "1", "--password-stdin")
	if err != nil || !strings.Contains(out, "previous content saved as rev 2") {
		t.Fatalf("%v\n%s", err, out)
	}
}
