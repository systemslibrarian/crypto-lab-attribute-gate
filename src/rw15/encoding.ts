/** Canonical identifiers for the bounded RW15 teaching profile. */

const ATTRIBUTE_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;
const GID = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,95}$/;

const encoder = new TextEncoder();

function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function frame(type: string, value: string): Uint8Array {
  const typeBytes = encoder.encode(type);
  const valueBytes = encoder.encode(value);
  return concat(u32be(typeBytes.length), typeBytes, u32be(valueBytes.length), valueBytes);
}

export function canonicalAuthorityId(authority: string): string {
  if (!ATTRIBUTE_COMPONENT.test(authority)) {
    throw new Error(
      'RW15_AUTHORITY: use 1-48 case-sensitive ASCII letters, digits, dot, underscore, or hyphen',
    );
  }
  return authority;
}

export interface QualifiedAttribute {
  readonly attribute: string;
  readonly authority: string;
  readonly qualified: string;
}

/**
 * Parse the paper's `[attribute-id]@[authority-id]` spelling without silent
 * case folding or Unicode normalization. Those transformations could make two
 * authorities hash different byte strings for what a UI presents as one GID
 * or attribute.
 */
export function parseQualifiedAttribute(value: string): QualifiedAttribute {
  const first = value.indexOf('@');
  if (first <= 0 || first !== value.lastIndexOf('@') || first === value.length - 1) {
    throw new Error('RW15_ATTRIBUTE: expected exactly attribute@authority');
  }
  const attribute = value.slice(0, first);
  const authority = value.slice(first + 1);
  if (!ATTRIBUTE_COMPONENT.test(attribute)) {
    throw new Error(
      'RW15_ATTRIBUTE: attribute id must use 1-48 case-sensitive ASCII letters, digits, dot, underscore, or hyphen',
    );
  }
  canonicalAuthorityId(authority);
  return { attribute, authority, qualified: `${attribute}@${authority}` };
}

export function canonicalGid(gid: string): string {
  if (!GID.test(gid)) {
    throw new Error(
      'RW15_GID: use 1-96 case-sensitive ASCII letters, digits, dot, underscore, colon, plus, or hyphen',
    );
  }
  return gid;
}

/** Injective, versioned inputs for the two independent random oracles. */
export function rwGidHashInput(gid: string): Uint8Array {
  return concat(frame('RW15-v1', 'GID'), frame('value', canonicalGid(gid)));
}

export function rwAttributeHashInput(attribute: string): Uint8Array {
  const qualified = parseQualifiedAttribute(attribute).qualified;
  return concat(frame('RW15-v1', 'ATTRIBUTE'), frame('value', qualified));
}
