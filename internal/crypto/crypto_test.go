package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	DefaultArgon = ArgonParams{Memory: 8 * 1024, Time: 1, Threads: 1} // fast tests
	os.Exit(m.Run())
}

func mustKey(t *testing.T) *VaultKey {
	t.Helper()
	k, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen(t *testing.T) {
	k := mustKey(t)
	if !strings.HasPrefix(k.Recipient(), "age1pq1") {
		t.Fatalf("expected hybrid PQ recipient, got %.12s…", k.Recipient())
	}
	msg := []byte("DATABASE_URL=postgres://app:hunter2@db/app\n")
	ct, err := Seal(k.Recipient(), msg) // public key only
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("hunter2")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := k.Open(ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open: %v %q", err, got)
	}
	ct2, _ := Seal(k.Recipient(), msg)
	if bytes.Equal(ct, ct2) {
		t.Fatal("sealing must be randomized")
	}
	if _, err := mustKey(t).Open(ct); err == nil {
		t.Fatal("other vault key opened the blob")
	}
	ct[len(ct)-1] ^= 1
	if _, err := k.Open(ct); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func TestSealTooLarge(t *testing.T) {
	if _, err := Seal(mustKey(t).Recipient(), make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestMAC(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	d := []byte("A=1")
	if !bytes.Equal(a.MAC(d), a.MAC(d)) {
		t.Fatal("MAC not deterministic")
	}
	if bytes.Equal(a.MAC(d), b.MAC(d)) {
		t.Fatal("MAC must depend on the vault key")
	}
}

func TestFingerprint(t *testing.T) {
	k := mustKey(t)
	fp := Fingerprint(k.Recipient())
	if len(fp) != 19 || strings.Count(fp, ":") != 3 || fp != Fingerprint(k.Recipient()) {
		t.Fatalf("bad fingerprint %q", fp)
	}
}

func TestRecoveryKey(t *testing.T) {
	k, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	s := k.String()
	if !strings.HasPrefix(s, "SME1-") || strings.Count(s, "-") != 13 || len(s) != 69 {
		t.Fatalf("bad format %q (len %d)", s, len(s))
	}
	variants := []string{s, strings.ToLower(s), strings.ReplaceAll(s, "-", " "), strings.ReplaceAll(s, "-", "")}
	for _, v := range variants {
		got, err := ParseRecoveryKey(v)
		if err != nil || got != k {
			t.Fatalf("parse(%q): %v", v, err)
		}
	}

	var fixed RecoveryKey
	for i := range fixed {
		fixed[i] = byte(i * 7)
	}
	fs := fixed.String()
	typo := []byte(fs)
	typo[10] = map[bool]byte{true: 'Z', false: 'Y'}[typo[10] != 'Z']
	if _, err := ParseRecoveryKey(string(typo)); !errors.Is(err, ErrBadRecoveryKey) {
		t.Fatalf("typo not caught: %v", err)
	}
	for _, bad := range []string{"", "SME1", "SME2-" + fs[5:], fs + "AAAA"} {
		if _, err := ParseRecoveryKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func newFile(t *testing.T) (*VaultKey, RecoveryKey, *KeyFile) {
	t.Helper()
	k := mustKey(t)
	rk, _ := NewRecoveryKey()
	f, err := NewKeyFile(k, "correct horse battery", rk)
	if err != nil {
		t.Fatal(err)
	}
	return k, rk, f
}

// roundtrip through JSON like the real on-disk file
func reload(t *testing.T, f *KeyFile) *KeyFile {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var g KeyFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

func TestKeyFileUnlock(t *testing.T) {
	k, rk, f := newFile(t)
	f = reload(t, f)

	if _, err := NewKeyFile(k, "short", rk); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password accepted: %v", err)
	}
	got, err := f.UnlockWithPassword("correct horse battery")
	if err != nil || got.Recipient() != k.Recipient() {
		t.Fatalf("password unlock: %v", err)
	}
	if _, err := f.UnlockWithPassword("wrong horse battery"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("want ErrWrongPassword, got %v", err)
	}
	got, err = f.UnlockWithRecovery(rk)
	if err != nil || got.Recipient() != k.Recipient() {
		t.Fatalf("recovery unlock: %v", err)
	}
	other, _ := NewRecoveryKey()
	if _, err := f.UnlockWithRecovery(other); !errors.Is(err, ErrWrongRecovery) {
		t.Fatalf("want ErrWrongRecovery, got %v", err)
	}

	// unlocked key can open data sealed to the recipient
	ct, _ := Seal(f.Recipient, []byte("A=1"))
	if pt, err := got.Open(ct); err != nil || string(pt) != "A=1" {
		t.Fatalf("open after unlock: %v", err)
	}
}

func TestChangePasswordKeepsRecovery(t *testing.T) {
	k, rk, f := newFile(t)
	if err := f.SetPassword(k, "a brand new passphrase"); err != nil {
		t.Fatal(err)
	}
	f = reload(t, f)
	if _, err := f.UnlockWithPassword("correct horse battery"); !errors.Is(err, ErrWrongPassword) {
		t.Fatal("old password still works")
	}
	if _, err := f.UnlockWithPassword("a brand new passphrase"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if _, err := f.UnlockWithRecovery(rk); err != nil {
		t.Fatalf("recovery after password change: %v", err)
	}
	if err := f.SetPassword(mustKey(t), "a brand new passphrase"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("rewrapping a different vault key must fail")
	}
}

func TestKeyFileTampering(t *testing.T) {
	_, rk, f := newFile(t)

	t.Run("swap wrapped blobs between methods", func(t *testing.T) {
		g := reload(t, f)
		g.Recovery.Ciphertext, g.Password.Ciphertext = g.Password.Ciphertext, g.Recovery.Ciphertext
		if _, err := g.UnlockWithRecovery(rk); err == nil {
			t.Fatal("swapped blob unlocked")
		}
	})
	t.Run("recipient replaced (attacker's key)", func(t *testing.T) {
		g := reload(t, f)
		g.Recipient = mustKey(t).Recipient()
		if _, err := g.UnlockWithPassword("correct horse battery"); err == nil {
			t.Fatal("unlocked with substituted recipient")
		}
	})
	t.Run("argon params downgraded", func(t *testing.T) {
		g := reload(t, f)
		g.Password.Argon = &ArgonParams{Memory: 1, Time: 1, Threads: 1}
		if _, err := g.UnlockWithPassword("correct horse battery"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("want ErrCorrupt, got %v", err)
		}
	})
	t.Run("flipped ciphertext bit", func(t *testing.T) {
		g := reload(t, f)
		g.Password.Ciphertext[0] ^= 1
		if _, err := g.UnlockWithPassword("correct horse battery"); err == nil {
			t.Fatal("tampered blob unlocked")
		}
	})
	t.Run("unknown version", func(t *testing.T) {
		g := reload(t, f)
		g.Version = 99
		if _, err := g.UnlockWithPassword("correct horse battery"); err == nil {
			t.Fatal("unknown version accepted")
		}
	})
}

func TestKeyFileHasNoPlaintextSecret(t *testing.T) {
	k, rk, f := newFile(t)
	b, _ := json.Marshal(f)
	for _, s := range []string{string(k.secret()), "correct horse battery", rk.String()} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("key file leaks a secret")
		}
	}
}

func BenchmarkUnlockDefaultArgon(b *testing.B) {
	DefaultArgon = ArgonParams{Memory: 64 * 1024, Time: 3, Threads: 4}
	k, _ := NewVaultKey()
	rk, _ := NewRecoveryKey()
	f, _ := NewKeyFile(k, "correct horse battery", rk)
	for b.Loop() {
		_, _ = f.UnlockWithPassword("correct horse battery")
	}
}

func TestDeviceCert(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	pub := []byte("device-public-key-32-bytes------")
	cert := a.CertifyDevice(pub)
	if !a.VerifyDeviceCert(pub, cert) {
		t.Fatal("own cert rejected")
	}
	if b.VerifyDeviceCert(pub, cert) {
		t.Fatal("cert from another vault accepted")
	}
	if a.VerifyDeviceCert([]byte("other-device-public-key-32-bytes"), cert) {
		t.Fatal("cert transferable to another device key")
	}
	if bytes.Equal(cert, a.MAC(pub)) {
		t.Fatal("cert key must be separate from the MAC key")
	}
}
