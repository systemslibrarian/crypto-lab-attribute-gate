/**
 * Randomness for FAME.
 *
 * Two sources, and the distinction matters for what this lab claims:
 *
 *  - `secureRandom` draws from `crypto.getRandomValues`. This is what the page
 *    uses. Every key really is randomized with fresh per-user values, which is
 *    the only reason the collusion exhibit is a demonstration rather than a
 *    dramatisation.
 *
 *  - `seededRandom(seed)` derives scalars deterministically from a label. It is
 *    used ONLY to pin the known-answer vectors, so `verify.py` can recompute
 *    every group element in a second, independent implementation and compare
 *    byte for byte. It is never used to encrypt anything on the page.
 *
 * The seeded derivation is defined so it can be reimplemented in ten lines of
 * Python: 64 bytes of SHA-256 output, big-endian, reduced mod p. The reduction
 * bias is below 2^-250 and it is a test fixture, not a key generator.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { mod, ORDER } from './bls';

export interface RandomSource {
  /**
   * A scalar in Z_p. `label` names the value in the scheme (`a1`, `r1`,
   * `sigma:Doctor`, ...) so a seeded source is reproducible and a secure source
   * can ignore it.
   */
  scalar(label: string): bigint;
  /** A scalar in Z_p^* (non-zero), for a1, a2, b1, b2. */
  nonZeroScalar(label: string): bigint;
  /** Raw bytes, for the AEAD nonce and the encapsulated GT element's exponent. */
  bytes(label: string, n: number): Uint8Array;
  readonly kind: 'secure' | 'seeded';
}

function bytesToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

export const secureRandom: RandomSource = {
  kind: 'secure',
  scalar(): bigint {
    // 64 bytes reduced mod p: the same negligible-bias construction RFC 9380
    // uses for hash_to_field, applied to a CSPRNG instead of a hash.
    const b = new Uint8Array(64);
    crypto.getRandomValues(b);
    return mod(bytesToBigInt(b));
  },
  nonZeroScalar(label: string): bigint {
    for (;;) {
      const x = this.scalar(label);
      if (x !== 0n) return x;
    }
  },
  bytes(_label: string, n: number): Uint8Array {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  },
};

const enc = new TextEncoder();

/**
 * Deterministic source for the pinned vectors.
 *
 * scalar(label) = OS2IP( SHA-256(seed || label || 0x00) ||
 *                        SHA-256(seed || label || 0x01) ) mod p
 */
export function seededRandom(seed: string): RandomSource {
  const seedBytes = enc.encode(seed);
  const block = (label: string, counter: number): Uint8Array => {
    const lab = enc.encode(label);
    const buf = new Uint8Array(seedBytes.length + lab.length + 1);
    buf.set(seedBytes, 0);
    buf.set(lab, seedBytes.length);
    buf[buf.length - 1] = counter;
    return sha256(buf);
  };
  const stream = (label: string, n: number): Uint8Array => {
    const out = new Uint8Array(n);
    let o = 0;
    for (let c = 0; o < n; c++) {
      const chunk = block(label, c);
      const take = Math.min(chunk.length, n - o);
      out.set(chunk.subarray(0, take), o);
      o += take;
    }
    return out;
  };
  const src: RandomSource = {
    kind: 'seeded',
    scalar(label: string): bigint {
      return mod(bytesToBigInt(stream(label, 64)));
    },
    nonZeroScalar(label: string): bigint {
      let x = src.scalar(label);
      let n = 0;
      while (x === 0n) x = src.scalar(`${label}#${++n}`);
      return x;
    },
    bytes(label: string, n: number): Uint8Array {
      return stream(`bytes:${label}`, n);
    },
  };
  return src;
}

/** Guard used by the tests: every scalar the scheme draws must be in range. */
export function inField(x: bigint): boolean {
  return x >= 0n && x < ORDER;
}
