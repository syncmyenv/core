package remote

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/vault"
	"github.com/syncmyenv/core/protocol"
)

// Syncer pushes local revisions to the server and pulls other devices' ones.
type Syncer struct {
	V      *vault.Vault // nil on a fresh machine until the keyring is fetched
	Cfg    *Config
	Client *protocol.Client
}

// ErrNotAuthorized means this device has no certificate yet: run `sme sync`
// interactively once (it asks for the master password to certify the device).
var ErrNotAuthorized = errors.New("this device isn't authorized to push yet — run `sme sync` once (asks for your master password)")

// Authorize certifies this device's signing key with the unlocked vault key.
// Needed once per device; afterwards pushes are password-free.
func (s *Syncer) Authorize(ctx context.Context, key *crypto.VaultKey) error {
	dk, err := s.V.DeviceKey()
	if err != nil {
		return err
	}
	return s.V.SetDeviceCert(ctx, key.CertifyDevice(dk.Public().(ed25519.PublicKey)))
}

// Authorized reports whether this device has a certificate.
func (s *Syncer) Authorized(ctx context.Context) bool {
	c, err := s.V.DeviceCert(ctx)
	return err == nil && len(c) > 0
}

// ErrNoRemoteVault means the account has no vault yet and there's no local one to upload.
var ErrNoRemoteVault = errors.New("no vault on this account yet — run `sme init` on your main machine and `sme sync` there first")

// EnsureVault links the local vault to a server vault, creating it (and
// uploading the keyring) on first sync. Returns whether it was created.
func (s *Syncer) EnsureVault(ctx context.Context) (created bool, err error) {
	kf := s.V.KeyFile()
	fp := crypto.Fingerprint(kf.Recipient)
	if s.Cfg.VaultID == "" {
		vaults, err := s.Client.Vaults(ctx)
		if err != nil {
			return false, err
		}
		for _, v := range vaults {
			if v.Fingerprint == fp {
				s.Cfg.VaultID = v.ID
			}
		}
		if s.Cfg.VaultID == "" {
			host, _ := os.Hostname()
			v, err := s.Client.CreateVault(ctx, "vault "+fp+" (from "+host+")")
			if err != nil {
				return false, err
			}
			s.Cfg.VaultID, created = v.ID, true
		}
		if err := s.Cfg.Save(); err != nil {
			return created, err
		}
	}
	// Upload/refresh the keyring (idempotent; password changes propagate).
	b, err := json.Marshal(kf)
	if err != nil {
		return created, err
	}
	if err := s.Client.PutKeyring(ctx, s.Cfg.VaultID, b); err != nil {
		if protocol.IsStatus(err, http.StatusConflict) {
			return created, fmt.Errorf("the server vault belongs to a different key than this machine's vault (%s) — refusing to mix them", fp)
		}
		return created, err
	}
	return created, s.V.SetState(ctx, "vault_id", s.Cfg.VaultID)
}

// Push uploads every unpushed local revision. Needs no password: revisions are
// already sealed, and metadata payloads are sealed to the public recipient.
func (s *Syncer) Push(ctx context.Context) (int, error) {
	if s.Cfg.VaultID == "" {
		return 0, errors.New("vault not linked yet — run `sme sync`")
	}
	cert, err := s.V.DeviceCert(ctx)
	if err != nil {
		return 0, err
	}
	if len(cert) == 0 {
		return 0, ErrNotAuthorized
	}
	dk, err := s.V.DeviceKey()
	if err != nil {
		return 0, err
	}
	pub := dk.Public().(ed25519.PublicKey)
	total := 0
	for {
		pending, err := s.V.Pending(ctx, protocol.MaxLogBatch)
		if err != nil || len(pending) == 0 {
			return total, err
		}
		first, err := s.V.NextDeviceSeq(ctx, len(pending))
		if err != nil {
			return total, err
		}
		entries := make([]protocol.LogEntry, 0, len(pending))
		revIDs := make([]string, 0, len(pending))
		objIDs := make([]string, 0, len(pending))
		for i, p := range pending {
			objID, err := s.Client.PutObject(ctx, s.Cfg.VaultID, p.Sealed)
			if err != nil {
				return total, err
			}
			payload, err := json.Marshal(protocol.EntryPayload{
				V: protocol.Version, Path: vault.ToPortable(p.Path), Project: p.Project,
				Size: p.Size, Source: p.Source, Device: p.Device, CreatedAt: p.CreatedAt,
			})
			if err != nil {
				return total, err
			}
			sealed, err := crypto.Seal(s.V.KeyFile().Recipient, payload)
			if err != nil {
				return total, err
			}
			seq := first + int64(i)
			entries = append(entries, protocol.LogEntry{
				DeviceSeq: seq, ObjectID: objID, Payload: sealed,
				DeviceKey: pub, DeviceCert: cert,
				Signature: ed25519.Sign(dk, protocol.SigningMessage(s.Cfg.VaultID, seq, objID, sealed)),
			})
			revIDs, objIDs = append(revIDs, p.RevisionID), append(objIDs, objID)
		}
		if err := s.Client.AppendLog(ctx, s.Cfg.VaultID, entries); err != nil {
			return total, err
		}
		if err := s.V.MarkPushed(ctx, revIDs, objIDs); err != nil {
			return total, err
		}
		total += len(pending)
	}
}

// Incoming counts log entries from other devices not yet pulled (no key needed).
func (s *Syncer) Incoming(ctx context.Context) ([]protocol.StoredEntry, int64, error) {
	cur, err := s.V.State(ctx, "pull_cursor")
	if err != nil {
		return nil, 0, err
	}
	since, _ := strconv.ParseInt(cur, 10, 64)
	var out []protocol.StoredEntry
	for {
		page, err := s.Client.ReadLog(ctx, s.Cfg.VaultID, since)
		if err != nil {
			return nil, 0, err
		}
		for _, e := range page.Entries {
			if e.DeviceID != s.Cfg.DeviceID {
				out = append(out, e)
			}
		}
		since = page.Next
		if !page.More {
			return out, since, nil
		}
	}
}

// PullResult summarizes a pull.
type PullResult struct {
	Imported []vault.ImportResult
	Rejected int // entries that failed authentication (forged or corrupted) — skipped
}

// Pull verifies and imports entries (from Incoming) with the unlocked vault
// key, then advances the cursor. Every entry must carry a device certificate
// made with *this vault's* key and a valid signature from that device;
// anything else — e.g. something the server made up — is rejected.
func (s *Syncer) Pull(ctx context.Context, key *crypto.VaultKey, entries []protocol.StoredEntry, cursor int64) (*PullResult, error) {
	res := &PullResult{}
	for _, e := range entries {
		if len(e.DeviceKey) != ed25519.PublicKeySize ||
			!key.VerifyDeviceCert(e.DeviceKey, e.DeviceCert) ||
			!ed25519.Verify(e.DeviceKey, protocol.SigningMessage(s.Cfg.VaultID, e.DeviceSeq, e.ObjectID, e.Payload), e.Signature) {
			res.Rejected++
			continue
		}
		raw, err := key.Open(e.Payload)
		if err != nil {
			res.Rejected++
			continue
		}
		var p protocol.EntryPayload
		if err := json.Unmarshal(raw, &p); err != nil || !vault.SafeImportPath(p.Path) {
			res.Rejected++
			continue
		}
		obj, err := s.Client.GetObject(ctx, s.Cfg.VaultID, e.ObjectID)
		if err != nil {
			return res, err
		}
		r, err := s.V.ImportRemote(ctx, key, p, e.DeviceID, e.ObjectID, obj)
		if err != nil {
			return res, err
		}
		if r.Seq > 0 {
			res.Imported = append(res.Imported, *r)
		}
	}
	return res, s.V.SetState(ctx, "pull_cursor", strconv.FormatInt(cursor, 10))
}

// FetchKeyring downloads the account's vault key file on a machine that has
// no local vault yet (new laptop). It picks the account's only vault, or the
// one matching wantFingerprint.
func FetchKeyring(ctx context.Context, cfg *Config, c *protocol.Client, wantFingerprint string) (*crypto.KeyFile, error) {
	vaults, err := c.Vaults(ctx)
	if err != nil {
		return nil, err
	}
	var candidates []protocol.Vault
	for _, v := range vaults {
		if v.Fingerprint != "" && (wantFingerprint == "" || v.Fingerprint == wantFingerprint) {
			candidates = append(candidates, v)
		}
	}
	switch len(candidates) {
	case 0:
		return nil, ErrNoRemoteVault
	case 1:
	default:
		return nil, fmt.Errorf("this account has %d vaults — pass --vault <fingerprint>", len(candidates))
	}
	b, err := c.GetKeyring(ctx, candidates[0].ID)
	if err != nil {
		return nil, err
	}
	var kf crypto.KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, crypto.ErrCorrupt
	}
	if crypto.Fingerprint(kf.Recipient) != candidates[0].Fingerprint {
		return nil, errors.New("server returned a keyring that doesn't match the vault fingerprint")
	}
	cfg.VaultID = candidates[0].ID
	return &kf, cfg.Save()
}
