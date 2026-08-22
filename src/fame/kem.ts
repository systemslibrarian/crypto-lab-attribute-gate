/**
 * Hybrid encryption: FAME as a KEM, HKDF-SHA-256 as the KDF, AES-256-GCM as the AEAD.
 *
 * WHY THE SPLIT EXISTS. FAME's message space is GT -- one element of Fp12, 576
 * bytes with almost no usable entropy budget of your own choosing. A patient
 * record does not fit in it, and breaking the record into GT-sized pieces and
 * ABE-encrypting each would be absurdly expensive. The paper says so directly:
 *
 *   "The standard method is to use a key encapsulation mechanism (KEM) wherein
 *    a random element of GT is ABE encrypted and hashed to derive a session
 *    key. This key is then used to encrypt the plaintext data through a fast
 *    symmetric key scheme like AES."
 *
 * So the pipeline is:
 *
 *   random K in GT  --FAME.Encrypt under the policy-->  ct'
 *   K --serialize--> 576 bytes --HKDF-SHA-256--> 32-byte AES key
 *   record --AES-256-GCM--> ciphertext + 128-bit tag
 *
 * The policy guards K. K guards the AES key. The AES key guards the record.
 * Nothing about the record is attribute-based; it is ordinary AEAD, and the
 * boundary is drawn on screen rather than assumed. HPKE Envelope teaches the
 * same KEM/KDF/AEAD shape with a DH KEM instead of an ABE one.
 *
 * The AEAD is also what makes failure honest. When a pooled key recovers the
 * wrong GT element, nothing in FAME notices -- decryption returns a perfectly
 * well-formed group element. It is the GCM tag that refuses.
 *
 * HKDF and AES-GCM come from WebCrypto (SubtleCrypto), not from a hand-rolled
 * implementation: they are not the teaching subject here, and using the
 * browser's own primitives is the point of the boundary.
 */
import { gtToBytes, type GTElement } from './bls';
import type { RandomSource } from './rand';

/** HKDF info string. Binds the derived key to this lab and this pipeline stage. */
export const HKDF_INFO = 'crypto-lab-attribute-gate/FAME-KEM/AES-256-GCM/v1';

/** Fixed, published salt. HKDF's salt is not required to be secret. */
export const HKDF_SALT = 'crypto-lab-attribute-gate/FAME-KEM/salt/v1';

export const AES_KEY_BITS = 256;
export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * RFC 5869 HKDF-SHA-256, via WebCrypto.
 *
 * Exposed on its own so the RFC's published test vectors can be run against
 * exactly the call this lab makes -- a KAT on a wrapper that nothing else uses
 * would prove nothing about the pipeline.
 */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
    base,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-SHA-256 over the serialized GT element.
 *
 * Extract-then-expand over all 576 bytes of the Fp12 encoding rather than over
 * a truncation: the encoding has structure, and hashing the whole thing is
 * both simpler to justify and what the paper's "hashed to derive a session
 * key" means.
 */
export async function deriveAesKey(shared: GTElement): Promise<{
  key: CryptoKey;
  rawKey: Uint8Array;
  ikm: Uint8Array;
}> {
  const ikm = gtToBytes(shared);
  const rawKey = await hkdfSha256(
    ikm,
    enc.encode(HKDF_SALT),
    enc.encode(HKDF_INFO),
    AES_KEY_BITS / 8,
  );
  const key = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
  return { key, rawKey, ikm };
}

/**
 * AES-256-GCM directly over raw key bytes, for the published test vectors.
 *
 * `sealRecord` derives its key and reaches the same WebCrypto call; running
 * NIST/Wycheproof vectors through this proves the nonce and AAD are wired the
 * way the standard says, which is the part a lab can get wrong.
 */
export async function aesGcmEncrypt(
  rawKey: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ]);
  const buf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return new Uint8Array(buf);
}

export interface SealedRecord {
  /** AES-256-GCM ciphertext with the 16-byte tag appended, as WebCrypto returns it. */
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  /** Additional authenticated data: the policy string, bound to the record. */
  readonly aad: string;
}

/**
 * AES-256-GCM over the record.
 *
 * The policy string goes in as AAD, so a ciphertext moved under a different
 * stated policy fails to open even if an attacker somehow had the key. That is
 * a property of the AEAD, not of ABE, and the page says so.
 */
export async function sealRecord(
  shared: GTElement,
  plaintext: string,
  aad: string,
  rng: RandomSource,
  nonceLabel = 'gcm',
): Promise<SealedRecord> {
  const { key } = await deriveAesKey(shared);
  const nonce = rng.bytes(nonceLabel, GCM_NONCE_BYTES);
  const buf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: enc.encode(aad) as BufferSource },
    key,
    enc.encode(plaintext) as BufferSource,
  );
  return { ciphertext: new Uint8Array(buf), nonce, aad };
}

export type OpenResult =
  | { readonly ok: true; readonly plaintext: string }
  | { readonly ok: false; readonly reason: 'AEAD_TAG_REJECTED' };

/**
 * Try to open the record with a candidate GT element.
 *
 * Returns a rejection rather than throwing: a failed tag is an outcome this
 * lab is trying to produce on purpose, not an exception.
 */
export async function openRecord(
  candidate: GTElement,
  sealed: SealedRecord,
): Promise<OpenResult> {
  const { key } = await deriveAesKey(candidate);
  try {
    const buf = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: sealed.nonce as BufferSource,
        additionalData: enc.encode(sealed.aad) as BufferSource,
      },
      key,
      sealed.ciphertext as BufferSource,
    );
    return { ok: true, plaintext: dec.decode(buf) };
  } catch {
    return { ok: false, reason: 'AEAD_TAG_REJECTED' };
  }
}

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
