package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
)

// A recovery key is 240 random bits + a 16-bit checksum, written in Crockford
// base32 (no I, L, O, U) as 13 groups of 4:
//
//	SME1-7QK2-M4XW-…-R9TD
//
// The checksum catches typos before we burn an unlock attempt.
type RecoveryKey [30]byte

const recoveryPrefix = "SME1"

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// ErrBadRecoveryKey means the key is malformed or mistyped.
var ErrBadRecoveryKey = errors.New("invalid recovery key — check for typos")

// NewRecoveryKey returns a fresh random recovery key.
func NewRecoveryKey() (RecoveryKey, error) {
	var k RecoveryKey
	_, err := rand.Read(k[:])
	return k, err
}

func (k RecoveryKey) String() string {
	sum := sha256.Sum256(k[:])
	raw := append(append([]byte{}, k[:]...), sum[:2]...)
	enc := crockford.EncodeToString(raw) // 52 chars
	groups := []string{recoveryPrefix}
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:i+4])
	}
	return strings.Join(groups, "-")
}

// ParseRecoveryKey accepts any case, spaces or dashes, and Crockford look-alikes (I/L→1, O→0).
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	var k RecoveryKey
	s = strings.ToUpper(s)
	s = strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "I", "1", "L", "1", "O", "0").Replace(s)
	if !strings.HasPrefix(s, recoveryPrefix) {
		return k, ErrBadRecoveryKey
	}
	raw, err := crockford.DecodeString(strings.TrimPrefix(s, recoveryPrefix))
	if err != nil || len(raw) != 32 {
		return k, ErrBadRecoveryKey
	}
	sum := sha256.Sum256(raw[:30])
	if subtle.ConstantTimeCompare(sum[:2], raw[30:]) != 1 {
		return k, ErrBadRecoveryKey
	}
	copy(k[:], raw[:30])
	return k, nil
}
