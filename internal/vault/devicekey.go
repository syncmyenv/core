package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/syncmyenv/core/internal/config"
)

// DeviceKey is this machine's log-signing key (~/.syncmyenv/device.key, 0600).
// It never leaves the device. Its public half is certified by the vault key.
func (v *Vault) DeviceKey() (ed25519.PrivateKey, error) {
	home, err := config.Home()
	if err != nil {
		return nil, err
	}
	p := filepath.Join(home, "device.key")
	seed, err := os.ReadFile(p)
	if err == nil && len(seed) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	seed = make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, seed, 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// DeviceCert returns this device's certificate, if one has been issued.
func (v *Vault) DeviceCert(ctx context.Context) ([]byte, error) {
	s, err := v.State(ctx, "device_cert")
	if err != nil || s == "" {
		return nil, err
	}
	return hex.DecodeString(s)
}

// SetDeviceCert stores the certificate issued by an unlocked vault key.
func (v *Vault) SetDeviceCert(ctx context.Context, cert []byte) error {
	return v.SetState(ctx, "device_cert", hex.EncodeToString(cert))
}
