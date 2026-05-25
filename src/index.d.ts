/// <reference types="node" />

// ── Key encoding ──────────────────────────────────────────────────────────────

/** Encode an ML-KEM-768 public key as a `kxco1…` bech32m recipient string. */
export function encodePublicKey(pubkeyBytes: Uint8Array | Buffer): string

/** Decode a `kxco1…` bech32m string back to raw ML-KEM-768 public key bytes. */
export function decodePublicKey(str: string): Uint8Array

// ── Envelope ─────────────────────────────────────────────────────────────────

export interface RecipientEntry {
  /** 16 hex chars — first 8 bytes of SHA-256(pubkey) */
  kid:             string
  /** hex — 1088-byte ML-KEM-768 ciphertext */
  encapsulatedKey: string
  /** hex — AES-256-GCM(ss, nonce=0, ad=kid).encrypt(dek) */
  wrappedDek:      string
}

export interface EnvelopeHeader {
  recipients: RecipientEntry[]
  /** hex — 12-byte GCM nonce */
  nonce:   string
  created: string  // ISO 8601
}

export interface ParsedEnvelope {
  header:     EnvelopeHeader
  ciphertext: Buffer
}

/** Serialise an envelope header to the canonical KXCO-VAULT text format. */
export function serializeHeader(header: EnvelopeHeader): string

/** Parse a complete `.kxco` file buffer into header + binary ciphertext. */
export function parseEnvelope(buf: Buffer | Uint8Array): ParsedEnvelope

/** Parse only the text header of a `.kxco` file. */
export function parseHeaderText(text: string): EnvelopeHeader

// ── Cryptographic operations ──────────────────────────────────────────────────

/** Generate a random 32-byte data encryption key. */
export function generateDek(): Buffer

/** Generate a random 12-byte AES-GCM nonce. */
export function generateNonce(): Buffer

/** Compute the 16-hex-char key identifier from a public key. */
export function computeKid(pubkeyBytes: Uint8Array | Buffer): string

/** Wrap a DEK for a recipient using their ML-KEM shared secret + kid as AD. */
export function wrapDek(
  ss:  Uint8Array | Buffer,
  kid: string,
  dek: Uint8Array | Buffer,
): Buffer

/** Unwrap a DEK given the ML-KEM shared secret and kid. */
export function unwrapDek(
  ss:         Uint8Array | Buffer,
  kid:        string,
  wrappedDek: Uint8Array | Buffer,
): Buffer

/** Encrypt plaintext with AES-256-GCM. Returns ciphertext + 16-byte auth tag. */
export function encryptPayload(
  dek:       Uint8Array | Buffer,
  nonce:     Uint8Array | Buffer,
  ad:        string,
  plaintext: Uint8Array | Buffer,
): Buffer

/** Decrypt an AES-256-GCM payload. Throws on authentication failure. */
export function decryptPayload(
  dek:     Uint8Array | Buffer,
  nonce:   Uint8Array | Buffer,
  ad:      string,
  payload: Uint8Array | Buffer,
): Buffer

// ── Utility ───────────────────────────────────────────────────────────────────

/**
 * Resolve a recipient argument to raw public key bytes.
 * Accepts a `kxco1…` bech32m string or `@/path/to/keypair.kxco`.
 */
export function resolveRecipient(str: string): Uint8Array

/**
 * Read a `.kxco` identity file and return its public and secret key bytes.
 */
export function readIdentity(path: string): { publicKey: Uint8Array; secretKey: Uint8Array }

export class KxcoVaultError extends Error {
  name: 'KxcoVaultError'
}
