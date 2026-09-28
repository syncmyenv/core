# Security policy

SyncMyEnv holds people's secrets. We take reports seriously and will credit you
(unless you'd rather we didn't).

## Reporting a vulnerability

**Please don't open a public issue.** Instead, use GitHub's
[private vulnerability reporting](https://github.com/syncmyenv/core/security/advisories/new)
for this repository.

Include what you can: affected version (`sme --version`), steps to reproduce, impact.
We'll acknowledge within 72 hours and keep you updated until it's fixed.

## Scope

- The `sme` CLI / daemon and its crypto (`internal/crypto`), vault and sync code
- The sync protocol (`protocol/`, `docs/sync.md`)
- The install script and release artifacts

Especially interesting: anything that lets a **server** (or someone with only account
access) read, forge or roll back vault data, or makes the client write outside
protected env files.

## Verifying releases

Every release publishes `checksums.txt`, signed with [Sigstore cosign](https://docs.sigstore.dev)
(keyless, tied to this repo's release workflow), plus GitHub build provenance:

```bash
# checksum signature
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/syncmyenv/core/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# then the archive against the checksums
sha256sum --ignore-missing -c checksums.txt

# or: GitHub build provenance
gh attestation verify sme_*_darwin_arm64.tar.gz --repo syncmyenv/core
```

The `install.sh` script verifies SHA-256 always, and the cosign signature when `cosign` is installed.

## Design docs

- [docs/architecture.md](docs/architecture.md) — key hierarchy, vault, daemon
- [docs/sync.md](docs/sync.md) — protocol, authenticity, what leaks
