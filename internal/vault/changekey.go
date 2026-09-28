package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/syncmyenv/core/internal/config"
)

// The change key lets the daemon detect "did this file change?" without the
// vault password. It is device-local and never synced: it only protects
// against someone who can already read the plaintext .env files on this disk.
// Cross-device dedup (later) uses the vault key's MAC instead.
func loadChangeKey() ([]byte, error) {
	home, err := config.Home()
	if err != nil {
		return nil, err
	}
	p := filepath.Join(home, "change.key")
	k, err := os.ReadFile(p)
	if err == nil && len(k) == 32 {
		return k, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, k, 0o600)
}

func changeMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
