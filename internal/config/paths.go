// Package config resolves SyncMyEnv's on-disk locations.
package config

import (
	"os"
	"path/filepath"
)

// HomeEnv overrides the vault location (useful for tests and multiple vaults).
const HomeEnv = "SYNCMYENV_HOME"

// Home returns the SyncMyEnv data directory, default ~/.syncmyenv.
func Home() (string, error) {
	if h := os.Getenv(HomeEnv); h != "" {
		return filepath.Abs(h)
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".syncmyenv"), nil
}

// VaultDB is the path of the local SQLite vault.
func VaultDB() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "vault.db"), nil
}

// ExpandHome turns a leading "~" into the user's home directory.
func ExpandHome(p string) string {
	if p == "~" || len(p) > 1 && p[:2] == "~/" {
		if u, err := os.UserHomeDir(); err == nil {
			return filepath.Join(u, p[1:])
		}
	}
	return p
}
