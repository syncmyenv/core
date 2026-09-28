// Package crypto implements the SyncMyEnv key hierarchy on vetted libraries
// only (age, x/crypto) — no custom primitives.
//
//	master password ──argon2id──▶ KEK₁ ─┐
//	                                   ├─ XChaCha20-Poly1305 ─▶ vault identity
//	recovery key ─────hkdf─────▶ KEK₂ ─┘      (age hybrid: ML-KEM-768 + X25519)
//	                                                  │
//	                                      vault recipient (public key)
//	                                                  │
//	                     the daemon seals every revision to the recipient
//
// Sealing needs only the public recipient, so the daemon can run unattended
// without holding any secret. Opening (history, restore, share) needs the
// identity, which is only ever unwrapped in memory.
//
// The hybrid key is post-quantum: ciphertext synced today stays safe even if
// someone stores it and waits for a quantum computer.
package crypto
