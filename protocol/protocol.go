// Package protocol is the SyncMyEnv sync protocol: wire types shared by the
// CLI and the server, plus a small HTTP client.
//
// It is public on purpose. The server imports it (so client and server can't
// drift), and anyone auditing the zero-knowledge claim can read exactly what
// crosses the wire: account metadata, ciphertext, and opaque IDs. Never a
// plaintext value, path, or key.
//
// Model (works over any blob store; the server adds auth + push):
//
//	keyring            the wrapped vault key (keys.json) — safe to store remotely
//	objects/<id>       sealed revisions; id = hex(sha256(ciphertext)), immutable
//	log                append-only entries, each written by exactly one device
//	                   (device_id, device_seq) → object + sealed metadata payload
//
// Devices only ever append to their own sequence, so there are no write
// conflicts on the server; merging happens on the clients.
package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Version of the protocol spoken by this package.
const Version = 1

// Limits enforced by the server (and respected by the client).
const (
	MaxObjectSize  = 2 << 20 // bytes of ciphertext
	MaxPayloadSize = 16 << 10
	MaxLogBatch    = 200
)

// ObjectID is the content address of a ciphertext blob. Hashing ciphertext
// reveals nothing: age output is randomized.
func ObjectID(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return hex.EncodeToString(sum[:])
}

// ---- auth (RFC 8628 device flow) ----

type DeviceCodeRequest struct {
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key,omitempty"`
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

type DeviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Device      Device `json:"device"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Me struct {
	User   User    `json:"user"`
	Device *Device `json:"device"`
}

// ---- vaults ----

type Vault struct {
	ID string `json:"id"`
	// Fingerprint of the vault's public recipient, once a keyring is uploaded.
	// Lets a new device find "its" vault without decrypting anything.
	Fingerprint string `json:"fingerprint,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

type CreateVaultRequest struct {
	Name string `json:"name"`
}

type VaultList struct {
	Vaults []Vault `json:"vaults"`
}

// ---- log ----

// LogEntry is written by one device. Payload is sealed to the vault
// recipient; the server stores it opaquely.
//
// Authenticity: sealing to the vault recipient is something anyone who knows
// the public key can do — including the server. So each entry is signed by
// the device's Ed25519 key (Signature over SigningMessage), and the device key
// carries a certificate (DeviceCert) that only vault-key holders can create or
// verify. Clients drop entries that fail either check.
type LogEntry struct {
	DeviceSeq  int64  `json:"device_seq"`
	ObjectID   string `json:"object_id"`
	Payload    []byte `json:"payload"`     // sealed EntryPayload (base64 in JSON)
	DeviceKey  []byte `json:"device_key"`  // ed25519 public key
	DeviceCert []byte `json:"device_cert"` // HMAC(vault cert key, DeviceKey)
	Signature  []byte `json:"signature"`   // ed25519 over SigningMessage
}

type AppendLogRequest struct {
	Entries []LogEntry `json:"entries"`
}

type AppendLogResponse struct {
	Accepted int `json:"accepted"`
}

// StoredEntry is a log entry as read back, with server-assigned ordering.
type StoredEntry struct {
	ID         int64  `json:"id"` // global cursor, strictly increasing per vault
	DeviceID   string `json:"device_id"`
	DeviceSeq  int64  `json:"device_seq"`
	ObjectID   string `json:"object_id"`
	Payload    []byte `json:"payload"`
	DeviceKey  []byte `json:"device_key"`
	DeviceCert []byte `json:"device_cert"`
	Signature  []byte `json:"signature"`
	CreatedAt  int64  `json:"created_at"`
}

// SigningMessage binds a signature to the vault, the device's sequence number,
// the object and the exact sealed payload (no cut-and-paste between vaults,
// positions or objects).
func SigningMessage(vaultID string, deviceSeq int64, objectID string, payload []byte) []byte {
	ph := sha256.Sum256(payload)
	return []byte(fmt.Sprintf("syncmyenv/log-entry/v1\x00%s\x00%d\x00%s\x00%x", vaultID, deviceSeq, objectID, ph))
}

type ReadLogResponse struct {
	Entries []StoredEntry `json:"entries"`
	Next    int64         `json:"next"` // pass as ?since= to continue
	More    bool          `json:"more"`
}

// EntryPayload is the plaintext inside LogEntry.Payload. The server never sees it.
type EntryPayload struct {
	V         int    `json:"v"`
	Path      string `json:"path"`    // "~/Projects/app/.env" (home-relative when possible)
	Project   string `json:"project"` // display name
	Size      int    `json:"size"`
	Source    string `json:"source"` // protect | snapshot | restore
	Device    string `json:"device"` // human device name
	CreatedAt int64  `json:"created_at"`
}

// ---- errors ----

// ErrorBody is the server's error shape: {"error": {"code", "message"}}.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
