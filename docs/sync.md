# Sync protocol (v1)

Core ↔ server (SyncMyEnv Cloud or self-hosted — same code). Wire types and the
client live in the public [`protocol`](../protocol) package, which the server imports.

## Commands

```bash
sme login                      # SyncMyEnv Cloud
sme login env.mycompany.com    # self-hosted (https implied; localhost/LAN → http)
sme sync                       # push + pull (asks for the master password only if needed)
sme sync --push-only           # never asks once the device is authorized
sme logout                     # revokes this device's token, keeps the local vault
```

The daemon pushes automatically after every sealed change (and every 30s to retry).
New machine: `sme login` → `sme sync` (downloads the *encrypted* key file, asks the
password, pulls) → `sme restore --missing`.

## What the server stores

| Thing | Contents | Server can read? |
|---|---|---|
| keyring | `keys.json` — vault key wrapped by password / recovery key | no (only the public recipient) |
| `objects/<sha256>` | sealed revisions (age, ML-KEM-768 + X25519) | no |
| log entry | device id + seq, object id, **sealed** metadata (path, project, size, time), signature | no, except ids/sizes/timing |

Devices only append to their own `(device_id, device_seq)`; there are no write
conflicts server-side. Clients merge.

## Authenticity — why entries are signed

Sealing to the vault's public recipient is something **anyone who knows the public key can
do — including the server**. Without more, a malicious server could forge "revisions".

So:

1. Each device has an Ed25519 **signing key** (`~/.syncmyenv/device.key`, never leaves it).
2. On first `sme sync` the user unlocks the vault once, and the vault key **certifies** the
   device: `cert = HMAC(HKDF(vault identity, "device-cert-key"), device_pub)`.
   Only vault-key holders can make or check a cert — the server can't.
3. Every entry is signed over `vault_id ‖ device_seq ‖ object_id ‖ sha256(payload)`.
4. Pulling clients verify cert **and** signature, and drop anything else.
5. The server additionally verifies signatures and **pins** each device's signing key on first
   use, so a stolen device *token* alone can't write valid entries.
6. Defence in depth: imported paths must be `~/…` or absolute, contain no `..`, and name an env
   file (`.env`, `.env.*`, `env`, `env.*`, not templates). A compromised device can't make
   `restore` write `~/.bashrc`.

Tested end-to-end: a device logged into the *same account* but without the vault key injects a
well-formed, server-accepted entry → every other device rejects it.

## Merging

- Remote revisions are imported into local history (deduped by object id).
- **Fast-forward**: if the file on disk still equals this device's latest known revision, the
  remote content is written to disk.
- **Conflict**: if the file has local edits, disk wins for now; the remote version is in
  history (`sme history`, `sme restore --version N`). Nothing is lost.
  Per-key 3-way merge for `.env` files is planned.
- Missing files are only stored; `sme restore --missing` writes them.

## What leaks (honest list)

- Account email, device names, number of devices, timing of changes.
- Ciphertext sizes ≈ plaintext sizes (padding planned).
- Which object ids belong to which device.
- A malicious server can **withhold** or **replay** entries (availability), not forge or read them.
  Replays are harmless (dedup by object id).

## Tokens

`~/.syncmyenv/remote.json` (0600) holds the device bearer token. It can read/write the
account's *ciphertext* only and can't approve devices. Moving it to the OS keychain is planned.
