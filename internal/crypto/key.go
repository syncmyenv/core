package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"
)

// MaxPlaintext bounds what we'll seal/open. Env files are tiny; anything
// bigger is almost certainly a mistake (or an attack on memory).
const MaxPlaintext = 1 << 20

// ErrTooLarge is returned for plaintexts or ciphertexts above MaxPlaintext.
var ErrTooLarge = errors.New("crypto: data too large")

// VaultKey is the vault's secret identity. Keep it in memory only.
type VaultKey struct {
	id     *age.HybridIdentity
	macKey []byte
}

// NewVaultKey generates a fresh post-quantum hybrid vault key.
func NewVaultKey() (*VaultKey, error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}
	return newVaultKey(id)
}

func newVaultKey(id *age.HybridIdentity) (*VaultKey, error) {
	mac := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(id.String()), nil, []byte("syncmyenv/v1/mac-key"))
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, err
	}
	return &VaultKey{id: id, macKey: mac}, nil
}

// parseVaultKey restores a key from its secret encoding (AGE-SECRET-KEY-PQ-1…).
func parseVaultKey(secret []byte) (*VaultKey, error) {
	id, err := age.ParseHybridIdentity(string(secret))
	if err != nil {
		return nil, err
	}
	return newVaultKey(id)
}

func (k *VaultKey) secret() []byte { return []byte(k.id.String()) }

// Recipient is the public key revisions are sealed to (age1pq1…).
func (k *VaultKey) Recipient() string { return k.id.Recipient().String() }

// MAC is a keyed hash for change detection and dedup. Never store a bare
// hash of a secret: short .env values would be brute-forceable offline.
func (k *VaultKey) MAC(data []byte) []byte {
	h := hmac.New(sha256.New, k.macKey)
	h.Write(data)
	return h.Sum(nil)
}

// Open decrypts a sealed blob.
func (k *VaultKey) Open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) > MaxPlaintext+64<<10 {
		return nil, ErrTooLarge
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), k.id)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxPlaintext+1))
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	if len(out) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	return out, nil
}

// Seal encrypts plaintext to a vault recipient. It needs no secret.
func Seal(recipient string, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	r, err := age.ParseHybridRecipient(recipient)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Fingerprint is a short, human-comparable ID for a (very long) PQ recipient,
// e.g. "5c1e:9a07:33d2:fb18". Compare it across machines to be sure you're
// talking about the same vault.
func Fingerprint(recipient string) string {
	sum := sha256.Sum256([]byte(recipient))
	h := hex.EncodeToString(sum[:8])
	return strings.Join([]string{h[0:4], h[4:8], h[8:12], h[12:16]}, ":")
}
