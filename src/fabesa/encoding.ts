/**
 * Canonical encodings for the bounded FABESA CP-A2BE lesson.
 *
 * Figure 5 of Meng, Chen, Tian and Manulis (CCS 2024, ePrint 2024/986)
 * writes the two random-oracle inputs as `0 || u` and `1 || u`. A JavaScript
 * string concatenation is not an injective encoding of the structured
 * attribute u = (name, value), so this instantiation uses a versioned type tag,
 * a one-byte branch, and length-prefixed UTF-8 fields. Inputs must already be
 * NFC-normalized: silently normalizing a cryptographic identifier would make
 * two caller-visible strings share one group element.
 */

export const MAX_ATTRIBUTE_NAME_BYTES = 64;
export const MAX_ATTRIBUTE_VALUE_BYTES = 128;
export const MAX_CONTEXT_BYTES = 128;

const enc = new TextEncoder();
const ATTRIBUTE_TAG = enc.encode('CRYPTO-LAB/FABESA/CP-A2BE/ATTRIBUTE/v1');

export interface HiddenAttribute {
  /** Public category, for example `Department`. */
  readonly name: string;
  /** Hidden value, for example `Cardiology`. */
  readonly value: string;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error('CANONICAL_ENCODING: length is outside uint32');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** Reject UTF-16 strings TextEncoder would otherwise repair with U+FFFD. */
function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function canonicalUtf8(
  value: string,
  field: 'attribute name' | 'attribute value' | 'context',
  maxBytes: number,
  allowEmpty = false,
): Uint8Array {
  if (hasUnpairedSurrogate(value)) {
    throw new Error(`CANONICAL_ENCODING: ${field} contains an unpaired UTF-16 surrogate`);
  }
  if (value !== value.normalize('NFC')) {
    throw new Error(`CANONICAL_ENCODING: ${field} must already be NFC-normalized`);
  }
  if (/\p{Cc}/u.test(value)) {
    throw new Error(`CANONICAL_ENCODING: ${field} contains a control character`);
  }
  const bytes = enc.encode(value);
  if ((!allowEmpty && bytes.length === 0) || bytes.length > maxBytes) {
    const range = allowEmpty ? `0-${maxBytes}` : `1-${maxBytes}`;
    throw new Error(`CANONICAL_ENCODING: ${field} must encode to ${range} bytes`);
  }
  return bytes;
}

export function validateHiddenAttribute(attribute: HiddenAttribute): void {
  canonicalUtf8(attribute.name, 'attribute name', MAX_ATTRIBUTE_NAME_BYTES);
  canonicalUtf8(attribute.value, 'attribute value', MAX_ATTRIBUTE_VALUE_BYTES);
}

/**
 * Injective instantiation of the paper's H(branch || (name, value)) input.
 */
export function encodeHiddenAttribute(
  branch: 0 | 1,
  attribute: HiddenAttribute,
): Uint8Array {
  validateHiddenAttribute(attribute);
  const name = enc.encode(attribute.name);
  const value = enc.encode(attribute.value);
  return concatBytes([
    ATTRIBUTE_TAG,
    new Uint8Array([branch]),
    u32be(name.length),
    name,
    u32be(value.length),
    value,
  ]);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function concatCanonical(parts: readonly Uint8Array[]): Uint8Array {
  return concatBytes(parts);
}
