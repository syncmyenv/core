// Package crypto implements the SyncMyEnv key hierarchy using vetted
// libraries only (no custom primitives):
//
//	master password --Argon2id--> KEK --wraps--> vault identity (X25519)
//	recovery key    ------------> KEK --wraps--> vault identity
//
// The daemon encrypts new revisions to the vault's *public* key, so it can
// run unattended without holding any secret. Decrypting (history, restore,
// share) requires unlocking the identity. See docs/architecture.md.
package crypto
