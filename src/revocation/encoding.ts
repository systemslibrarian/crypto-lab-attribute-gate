/**
 * Canonical byte encodings for the bounded epoch-gating lesson.
 *
 * Every variable-width field is length-prefixed and every aggregate starts
 * with a versioned domain tag.  These encodings are part of the teaching
 * adaptation, not part of FAME or of a revocable-ABE specification.
 */
import { sha256 } from '@noble/hashes/sha2.js';

const encoder = new TextEncoder();

export function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error('CANONICAL_ENCODING: value is outside uint32');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Length-prefix every field, including fixed-width fields, to keep one rule. */
export function frame(tag: string, parts: readonly Uint8Array[]): Uint8Array {
  const tagged = [utf8(tag), ...parts];
  return concatBytes(tagged.flatMap((part) => [u32be(part.length), part]));
}

export function decimal(value: bigint): Uint8Array {
  return utf8(value.toString(10));
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('CANONICAL_ENCODING: malformed hexadecimal string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function digest(bytes: Uint8Array): Uint8Array {
  return sha256(bytes);
}

/** Constant-work for equal-length inputs; this lab makes no timing claim. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

export function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}
