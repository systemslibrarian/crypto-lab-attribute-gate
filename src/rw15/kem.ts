/** RW15-specific KEM/KDF/AEAD teaching wrapper. Not part of the RW15 theorem. */
import { gtToBytes, type GTElement } from '../fame/bls';
import type { RandomSource } from '../fame/rand';

export const RW15_HKDF_INFO = 'crypto-lab-attribute-gate/RW15-KEM/AES-256-GCM/v1';
export const RW15_HKDF_SALT = 'crypto-lab-attribute-gate/RW15-KEM/salt/v1';
export const RW15_GCM_NONCE_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function deriveKey(shared: GTElement): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    gtToBytes(shared) as BufferSource,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(RW15_HKDF_SALT) as BufferSource,
      info: encoder.encode(RW15_HKDF_INFO) as BufferSource,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface RwSealedRecord {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  /** Canonical policy/authority context supplied by the caller. */
  readonly aad: string;
}

export async function rwSealRecord(
  shared: GTElement,
  plaintext: string,
  aad: string,
  rng: RandomSource,
  nonceLabel = 'record',
): Promise<RwSealedRecord> {
  const key = await deriveKey(shared);
  const nonce = rng.bytes(`rw15:gcm:${nonceLabel}`, RW15_GCM_NONCE_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: encoder.encode(aad) as BufferSource,
    },
    key,
    encoder.encode(plaintext) as BufferSource,
  );
  return { ciphertext: new Uint8Array(ciphertext), nonce, aad };
}

export type RwOpenResult =
  | { readonly ok: true; readonly plaintext: string }
  | { readonly ok: false; readonly code: 'AEAD_TAG_REJECTED' | 'MALFORMED_RECORD' };

export async function rwOpenRecord(
  candidate: GTElement,
  record: RwSealedRecord,
): Promise<RwOpenResult> {
  if (
    !(record.nonce instanceof Uint8Array) ||
    record.nonce.length !== RW15_GCM_NONCE_BYTES ||
    !(record.ciphertext instanceof Uint8Array) ||
    record.ciphertext.length < 16 ||
    typeof record.aad !== 'string'
  ) {
    return { ok: false, code: 'MALFORMED_RECORD' };
  }
  const key = await deriveKey(candidate);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: record.nonce as BufferSource,
        additionalData: encoder.encode(record.aad) as BufferSource,
      },
      key,
      record.ciphertext as BufferSource,
    );
    return { ok: true, plaintext: decoder.decode(plaintext) };
  } catch (error) {
    if (error instanceof DOMException && error.name === 'OperationError') {
      return { ok: false, code: 'AEAD_TAG_REJECTED' };
    }
    throw error;
  }
}
