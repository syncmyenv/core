// Package remote stores this device's connection to a SyncMyEnv server
// (cloud or self-hosted) and syncs the vault with it.
package remote

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/protocol"
)

// DefaultServer is SyncMyEnv Cloud.
const DefaultServer = "https://cloud.syncmyenv.com"

// ErrNotLoggedIn means `sme login` hasn't been run.
var ErrNotLoggedIn = errors.New("not connected to a server — run `sme login`")

// Config is ~/.syncmyenv/remote.json (0600).
//
// The device token is a bearer secret. It can read/write this account's
// *ciphertext* only; it can't decrypt anything and can't approve devices.
// TODO: move the token to the OS keychain.
type Config struct {
	Server     string `json:"server"`
	Token      string `json:"token"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Email      string `json:"email"`
	VaultID    string `json:"vault_id,omitempty"`
}

func path() (string, error) {
	h, err := config.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "remote.json"), nil
}

// Load reads the remote config.
func Load() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotLoggedIn
	} else if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Token == "" || c.Server == "" {
		return nil, ErrNotLoggedIn
	}
	return &c, nil
}

// Save writes the remote config atomically with 0600.
func (c *Config) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Delete removes the remote config (logout).
func Delete() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Client returns an API client for this config.
func (c *Config) Client(version string) *protocol.Client {
	return &protocol.Client{BaseURL: c.Server, Token: c.Token, UA: "syncmyenv-cli/" + version}
}
