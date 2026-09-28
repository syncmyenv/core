package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ArgonParams are stored per key file, so they can be raised later without
// breaking existing vaults.
type ArgonParams struct {
	Memory  uint32 `json:"m"` // KiB
	Time    uint32 `json:"t"`
	Threads uint8  `json:"p"`
}

// DefaultArgon: 64 MiB, 3 passes, 4 lanes (~0.2–0.5s on a laptop).
var DefaultArgon = ArgonParams{Memory: 64 * 1024, Time: 3, Threads: 4}

// MinPasswordLen for the vault master password.
const MinPasswordLen = 12

var (
	ErrWrongPassword = errors.New("wrong master password")
	ErrWrongRecovery = errors.New("recovery key doesn't match this vault")
	ErrCorrupt       = errors.New("key file is corrupt or was tampered with")
	ErrWeakPassword  = fmt.Errorf("master password must be at least %d characters", MinPasswordLen)
)

// Wrapped is the vault identity encrypted under one unlock method.
type Wrapped struct {
	KDF        string       `json:"kdf"` // "argon2id" | "hkdf-sha256"
	Argon      *ArgonParams `json:"argon,omitempty"`
	Salt       []byte       `json:"salt"`
	Nonce      []byte       `json:"nonce"`
	Ciphertext []byte       `json:"ciphertext"`
}

// KeyFile is what's stored at ~/.syncmyenv/keys.json and (later) synced to
// remotes for new-device recovery. It contains no plaintext secret.
type KeyFile struct {
	Version   int       `json:"version"`
	Recipient string    `json:"recipient"`
	CreatedAt time.Time `json:"created_at"`
	Password  *Wrapped  `json:"password"`
	Recovery  *Wrapped  `json:"recovery"`
}

const keyFileVersion = 1

// NewKeyFile wraps k under both the master password and the recovery key.
func NewKeyFile(k *VaultKey, password string, rk RecoveryKey) (*KeyFile, error) {
	f := &KeyFile{Version: keyFileVersion, Recipient: k.Recipient(), CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := f.SetPassword(k, password); err != nil {
		return nil, err
	}
	w, err := wrap(k.secret(), recoveryKEK, rk[:], f.ad("recovery"), nil)
	if err != nil {
		return nil, err
	}
	f.Recovery = w
	return f, nil
}

// SetPassword (re)wraps k under a new master password. The recovery key and
// all sealed data are unaffected.
func (f *KeyFile) SetPassword(k *VaultKey, password string) error {
	if len(password) < MinPasswordLen {
		return ErrWeakPassword
	}
	if k.Recipient() != f.Recipient {
		return ErrCorrupt
	}
	p := DefaultArgon
	w, err := wrap(k.secret(), argonKEK, []byte(password), f.ad("password"), &p)
	if err != nil {
		return err
	}
	f.Password = w
	return nil
}

// UnlockWithPassword unwraps the vault key with the master password.
func (f *KeyFile) UnlockWithPassword(password string) (*VaultKey, error) {
	if f.Password == nil || f.Password.KDF != "argon2id" || f.Password.Argon == nil {
		return nil, ErrCorrupt
	}
	return f.unlock(f.Password, argonKEK, []byte(password), "password", ErrWrongPassword)
}

// UnlockWithRecovery unwraps the vault key with the recovery key.
func (f *KeyFile) UnlockWithRecovery(rk RecoveryKey) (*VaultKey, error) {
	if f.Recovery == nil || f.Recovery.KDF != "hkdf-sha256" {
		return nil, ErrCorrupt
	}
	return f.unlock(f.Recovery, recoveryKEK, rk[:], "recovery", ErrWrongRecovery)
}

func (f *KeyFile) unlock(w *Wrapped, kek kekFunc, secret []byte, method string, wrongErr error) (*VaultKey, error) {
	if f.Version != keyFileVersion {
		return nil, fmt.Errorf("crypto: unsupported key file version %d", f.Version)
	}
	key, err := kek(secret, w.Salt, w.Argon)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(w.Nonce) != aead.NonceSize() {
		return nil, ErrCorrupt
	}
	plain, err := aead.Open(nil, w.Nonce, w.Ciphertext, f.ad(method))
	if err != nil {
		return nil, wrongErr // wrong secret, or tampered file (indistinguishable by design)
	}
	k, err := parseVaultKey(plain)
	if err != nil || k.Recipient() != f.Recipient {
		return nil, ErrCorrupt
	}
	return k, nil
}

// ad binds each wrapped blob to its method and the vault's public key, so
// blobs can't be swapped between methods or between vaults.
func (f *KeyFile) ad(method string) []byte {
	return []byte(fmt.Sprintf("syncmyenv/keyfile/v%d/%s/%s", f.Version, method, f.Recipient))
}

type kekFunc func(secret, salt []byte, p *ArgonParams) ([]byte, error)

func argonKEK(pw, salt []byte, p *ArgonParams) ([]byte, error) {
	if p == nil || p.Memory < 8*1024 || p.Time < 1 || p.Threads < 1 {
		return nil, ErrCorrupt // refuse downgraded params from a tampered file
	}
	return argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, chacha20poly1305.KeySize), nil
}

func recoveryKEK(rk, salt []byte, _ *ArgonParams) ([]byte, error) {
	// The recovery key is 240 random bits: a fast KDF is enough.
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(hkdf.New(sha256.New, rk, salt, []byte("syncmyenv/v1/recovery-kek")), key)
	return key, err
}

func wrap(secret []byte, kek kekFunc, input, ad []byte, p *ArgonParams) (*Wrapped, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := kek(input, salt, p)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	w := &Wrapped{KDF: "hkdf-sha256", Salt: salt, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, secret, ad)}
	if p != nil {
		w.KDF, w.Argon = "argon2id", p
	}
	return w, nil
}
