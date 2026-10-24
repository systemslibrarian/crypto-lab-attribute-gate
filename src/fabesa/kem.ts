/**
 * Teaching KEM/DEM wrapper for the FABESA CP-A2BE core.
 *
 * This is NOT part of the construction or Theorem 4 in ePrint 2024/986. The
 * paper encrypts one GT element. This wrapper samples that element, derives an
 * AES-256 key with HKDF-SHA-256, and seals UTF-8 text with AES-GCM. Its tag is
 * also the candidate oracle section 3.3's trial procedure needs: in the
 * ordinary nondegenerate case, wrong hidden values produce a different GT
 * element and the tag rejects except with the tag's negligible forgery
 * probability. Paper-faithful zero scalars are handled and tested separately.
 * Unlike the authors' demonstration artifact, decrypt never receives the
 * expected plaintext or expected GT element as an input.
 */
import {
  ORDER,
  g1,
  g2,
  gtPow,
  gtToBytes,
  mod,
  pairing,
  pairingCount,
  type GTElement,
} from '../fame/bls';
import type { RandomSource } from '../fame/rand';
import {
  canonicalUtf8,
  concatCanonical,
  MAX_CONTEXT_BYTES,
  u32be,
} from './encoding';
import {
  decryptCandidate,
  encrypt,
  enumerateReconstructionCandidates,
  validatePublicPolicy,
  type Ciphertext,
  type EnumerationLimits,
  type HiddenPolicy,
  type PublicKey,
  type PublicPolicy,
  type ReconstructionCandidate,
  type SecretKey,
  validateCiphertext,
} from './fabesa';

export const FABESA_HKDF_INFO = 'crypto-lab-attribute-gate/FABESA-CP-A2BE-KEM/AES-256-GCM/v1';
export const FABESA_HKDF_SALT = 'crypto-lab-attribute-gate/FABESA-CP-A2BE-KEM/salt/v1';
export const FABESA_GCM_NONCE_BYTES = 12;

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export interface FabesaEnvelope {
  readonly abe: Ciphertext;
  readonly nonce: Uint8Array;
  /** AES-GCM ciphertext with its 128-bit tag appended. */
  readonly sealed: Uint8Array;
  /** Public lesson/application context, authenticated but not encrypted. */
  readonly context: string;
}

export interface CandidateAttempt {
  readonly candidate: ReconstructionCandidate;
  readonly tagAccepted: boolean;
  /** Executed pairing-counter delta, not the paper's nominal count. */
  readonly pairings: number;
}

export type OpenEnvelopeResult =
  | {
      readonly ok: true;
      readonly plaintext: string;
      readonly candidate: ReconstructionCandidate;
      readonly attempts: readonly CandidateAttempt[];
      readonly pairings: number;
    }
  | {
      readonly ok: false;
      readonly reason:
        | 'NO_PUBLIC_RECONSTRUCTION'
        | 'NO_CANDIDATE_OPENED'
        | 'MATCHED_ROW_BOUND_EXCEEDED'
        | 'CANDIDATE_BOUND_EXCEEDED';
      readonly attempts: readonly CandidateAttempt[];
      readonly subsetsExamined: number;
      readonly pairings: number;
    };

function scalarBytes(value: bigint): Uint8Array {
  let x = mod(value);
  const out = new Uint8Array(32);
  for (let index = out.length - 1; index >= 0; index--) {
    out[index] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** Canonical AAD: context plus the complete public policy payload. */
export function encodeEnvelopeAad(policy: PublicPolicy, context: string): Uint8Array {
  validatePublicPolicy(policy);
  const contextBytes = canonicalUtf8(context, 'context', MAX_CONTEXT_BYTES, true);
  const parts: Uint8Array[] = [
    enc.encode('CRYPTO-LAB/FABESA/CP-A2BE/ENVELOPE-AAD/v1'),
    u32be(contextBytes.length),
    contextBytes,
    u32be(policy.rows.length),
    u32be(policy.columns),
  ];
  for (const row of policy.rows) {
    const name = enc.encode(row.name);
    parts.push(u32be(row.index), u32be(name.length), name);
    for (const entry of row.vector) parts.push(scalarBytes(entry));
  }
  return concatCanonical(parts);
}

async function deriveAesKey(shared: GTElement): Promise<CryptoKey> {
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
      salt: enc.encode(FABESA_HKDF_SALT),
      info: enc.encode(FABESA_HKDF_INFO),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function randomSharedSecret(rng: RandomSource, nonce: string): GTElement {
  // A non-zero exponent avoids the identity, a degenerate event with
  // probability 1/p in the paper's uniform sampler.
  const exponent = rng.nonZeroScalar(`fabesa:kem${nonce === '' ? '' : `@${nonce}`}`);
  return gtPow(pairing(g1, g2), mod(exponent % ORDER));
}

export async function sealEnvelope(
  pk: PublicKey,
  policy: HiddenPolicy,
  plaintext: string,
  rng: RandomSource,
  context = '',
  nonce = '',
): Promise<FabesaEnvelope> {
  const shared = randomSharedSecret(rng, nonce);
  const abe = encrypt(pk, policy, shared, rng, nonce);
  const aad = encodeEnvelopeAad(abe.policy, context);
  const iv = rng.bytes(`fabesa:gcm${nonce === '' ? '' : `@${nonce}`}`, FABESA_GCM_NONCE_BYTES);
  const key = await deriveAesKey(shared);
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource },
    key,
    enc.encode(plaintext) as BufferSource,
  );
  return { abe, nonce: iv, sealed: new Uint8Array(sealed), context };
}

async function tryCandidate(
  envelope: FabesaEnvelope,
  candidate: ReconstructionCandidate,
  key: SecretKey,
): Promise<{ accepted: boolean; plaintext: string | null; pairings: number }> {
  const before = pairingCount();
  const shared = decryptCandidate(envelope.abe, key, candidate);
  const pairings = pairingCount() - before;
  const aes = await deriveAesKey(shared);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: envelope.nonce as BufferSource,
        additionalData: encodeEnvelopeAad(envelope.abe.policy, envelope.context) as BufferSource,
      },
      aes,
      envelope.sealed as BufferSource,
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === 'OperationError') {
      return { accepted: false, plaintext: null, pairings };
    }
    throw error;
  }
  // Fatal UTF-8 decoding is deliberately outside the authentication catch:
  // a valid tag over a non-text payload is a lesson/runtime error, not a
  // hidden-value candidate rejection.
  return { accepted: true, plaintext: dec.decode(plaintext), pairings };
}

export async function openEnvelope(
  envelope: FabesaEnvelope,
  key: SecretKey,
  limits?: Partial<EnumerationLimits>,
): Promise<OpenEnvelopeResult> {
  if (envelope.nonce.length !== FABESA_GCM_NONCE_BYTES) {
    throw new Error(`FABESA_ENVELOPE: AES-GCM nonce must be ${FABESA_GCM_NONCE_BYTES} bytes`);
  }
  if (envelope.sealed.length < 16) {
    throw new Error('FABESA_ENVELOPE: AES-GCM ciphertext is shorter than its tag');
  }
  validateCiphertext(envelope.abe);
  const enumeration = enumerateReconstructionCandidates(envelope.abe.policy, key, limits);
  if (!enumeration.ok) {
    return {
      ok: false,
      reason: enumeration.reason,
      attempts: [],
      subsetsExamined: enumeration.subsetsExamined,
      pairings: 0,
    };
  }
  if (enumeration.candidates.length === 0) {
    return {
      ok: false,
      reason: 'NO_PUBLIC_RECONSTRUCTION',
      attempts: [],
      subsetsExamined: enumeration.subsetsExamined,
      pairings: 0,
    };
  }

  const attempts: CandidateAttempt[] = [];
  for (const candidate of enumeration.candidates) {
    const result = await tryCandidate(envelope, candidate, key);
    attempts.push({
      candidate,
      tagAccepted: result.accepted,
      pairings: result.pairings,
    });
    if (result.accepted && result.plaintext !== null) {
      return {
        ok: true,
        plaintext: result.plaintext,
        candidate,
        attempts,
        pairings: attempts.reduce((sum, attempt) => sum + attempt.pairings, 0),
      };
    }
  }
  return {
    ok: false,
    reason: 'NO_CANDIDATE_OPENED',
    attempts,
    subsetsExamined: enumeration.subsetsExamined,
    pairings: attempts.reduce((sum, attempt) => sum + attempt.pairings, 0),
  };
}
