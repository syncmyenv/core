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
