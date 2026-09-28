package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
)

// ErrNotInitialized means `sme init` hasn't been run for this SYNCMYENV_HOME.
var ErrNotInitialized = errors.New("vault not initialized — run `sme init`")

// ErrAlreadyInitialized protects an existing vault key from being overwritten
// (that would make every revision sealed to it unrecoverable).
var ErrAlreadyInitialized = errors.New("vault already initialized")

// KeyFilePath is ~/.syncmyenv/keys.json.
func KeyFilePath() (string, error) {
	h, err := config.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "keys.json"), nil
}

// LoadKeyFile reads the wrapped vault key.
func LoadKeyFile() (*crypto.KeyFile, error) {
	p, err := KeyFilePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInitialized
	} else if err != nil {
		return nil, err
	}
	var f crypto.KeyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", p, crypto.ErrCorrupt)
	}
	return &f, nil
}

// CreateKeyFile writes a new key file, refusing to replace an existing one.
func CreateKeyFile(f *crypto.KeyFile) error {
	p, err := KeyFilePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return ErrAlreadyInitialized
	}
	return writeAtomic(p, f)
}

// UpdateKeyFile replaces the key file (e.g. after a password change).
func UpdateKeyFile(f *crypto.KeyFile) error {
	p, err := KeyFilePath()
	if err != nil {
		return err
	}
	return writeAtomic(p, f)
}

// writeAtomic writes via temp file + fsync + rename, so a crash can never
// leave a half-written key file (which would lock you out).
func writeAtomic(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keys-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
