/**
 * RW15 multi-authority CP-ABE, transcribed from Rouselakis-Waters FC 2015.
 *
 * The paper writes the construction in a symmetric group and explicitly says
 * its implementations use the asymmetric translation. The group placement
 * here follows the authors' implementation exactly:
 *
 *   H,F -> G2; authority Y, K', C2, C3 -> G1; K,C4 -> G2.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  addMod,
  g1,
  g1Mul,
  g1Pow,
  g2,
  g2Mul,
  g2Pow,
  gtDiv,
  gtMul,
  gtPow,
  mod,
  mulMod,
  pairing,
  pairingCount,
  type G1Point,
  type G2Point,
  type GTElement,
} from '../fame/bls';
import type { RandomSource } from '../fame/rand';
import {
  canonicalAuthorityId,
  canonicalGid,
  parseQualifiedAttribute,
  rwAttributeHashInput,
  rwGidHashInput,
} from './encoding';
import {
  reconstructRw,
  type RwLsss,
  type RwReconstruction,
} from './lsss';

export const RW15_GID_DST =
  'CRYPTO-LAB-ATTRIBUTE-GATE-RW15-GID-v1_BLS12381G2_XMD:SHA-256_SSWU_RO_';
export const RW15_ATTRIBUTE_DST =
  'CRYPTO-LAB-ATTRIBUTE-GATE-RW15-ATTR-v1_BLS12381G2_XMD:SHA-256_SSWU_RO_';

/** Fixed public generators are valid generators and make fixtures reproducible. */
export const RW15_EGG: GTElement = bls.pairing(g1, g2);

const gidHashCache = new Map<string, G2Point>();
const attributeHashCache = new Map<string, G2Point>();

export function rwHashGid(gid: string): G2Point {
  const canonical = canonicalGid(gid);
  const hit = gidHashCache.get(canonical);
  if (hit) return hit;
  const point = bls.G2.hashToCurve(rwGidHashInput(canonical), {
    DST: RW15_GID_DST,
  }) as G2Point;
  gidHashCache.set(canonical, point);
  return point;
}

export function rwHashAttribute(attribute: string): G2Point {
  const canonical = parseQualifiedAttribute(attribute).qualified;
  const hit = attributeHashCache.get(canonical);
  if (hit) return hit;
  const point = bls.G2.hashToCurve(rwAttributeHashInput(canonical), {
    DST: RW15_ATTRIBUTE_DST,
  }) as G2Point;
  attributeHashCache.set(canonical, point);
  return point;
}

export interface RwAuthorityPublicKey {
  readonly id: string;
  /** e(g1,g2)^alpha in GT. */
  readonly egga: GTElement;
  /** g1^y in G1. */
  readonly gy: G1Point;
}

export interface RwAuthoritySecretKey {
  readonly id: string;
  readonly alpha: bigint;
  readonly y: bigint;
}

export interface RwAuthority {
  readonly pk: RwAuthorityPublicKey;
  readonly sk: RwAuthoritySecretKey;
}

export interface RwAttributeKey {
  readonly gid: string;
  readonly attribute: string;
  readonly authority: string;
  /** g2^alpha H(GID)^y F(attribute)^t in G2. */
  readonly K: G2Point;
  /** g1^t in G1. */
  readonly KPrime: G1Point;
}

export interface RwKeyWitness {
  readonly t: bigint;
}

export interface RwCiphertextRow {
  readonly rowIndex: number;
  readonly attribute: string;
  readonly authority: string;
  readonly C1: GTElement;
  readonly C2: G1Point;
  readonly C3: G1Point;
  readonly C4: G2Point;
}

export interface RwCiphertext {
  readonly lsss: RwLsss;
  readonly C0: GTElement;
  readonly rows: readonly RwCiphertextRow[];
}

export interface RwRowWitness {
  readonly tx: bigint;
  readonly lambda: bigint;
  readonly omega: bigint;
}

export interface RwEncryptionWitness {
  readonly z: bigint;
  readonly v: readonly bigint[];
  readonly w: readonly bigint[];
  readonly rows: ReadonlyMap<number, RwRowWitness>;
  readonly message: GTElement;
}

function dot(row: readonly bigint[], vector: readonly bigint[]): bigint {
  if (row.length !== vector.length) throw new Error('RW15_LSSS: vector dimension mismatch');
  return row.reduce((sum, value, index) => addMod(sum, mulMod(value, vector[index])), 0n);
}

export function rwAuthoritySetup(
  authorityId: string,
  rng: RandomSource,
  nonce = '',
): RwAuthority {
  const id = canonicalAuthorityId(authorityId);
  const suffix = nonce === '' ? '' : `@${nonce}`;
  const alpha = rng.scalar(`rw15:authority:${id}:alpha${suffix}`);
  const y = rng.scalar(`rw15:authority:${id}:y${suffix}`);
  return {
    pk: { id, egga: gtPow(RW15_EGG, alpha), gy: g1Pow(g1, y) },
    sk: { id, alpha, y },
  };
}

export function rwKeygen(
  authority: RwAuthoritySecretKey,
  gidInput: string,
  attributeInput: string,
  rng: RandomSource,
  nonce = '',
): { readonly key: RwAttributeKey; readonly witness: RwKeyWitness } {
  const gid = canonicalGid(gidInput);
  const parsed = parseQualifiedAttribute(attributeInput);
  if (parsed.authority !== authority.id) {
    throw new Error(
      `RW15_AUTHORITY_MISMATCH: ${parsed.qualified} is controlled by ${parsed.authority}, not ${authority.id}`,
    );
  }
  const suffix = nonce === '' ? '' : `@${nonce}`;
  const t = rng.scalar(`rw15:key:${gid}:${parsed.qualified}:t${suffix}`);
  const K = g2Mul(
    g2Mul(g2Pow(g2, authority.alpha), g2Pow(rwHashGid(gid), authority.y)),
    g2Pow(rwHashAttribute(parsed.qualified), t),
  );
  return {
    key: {
      gid,
      attribute: parsed.qualified,
      authority: parsed.authority,
      K,
      KPrime: g1Pow(g1, t),
    },
    witness: { t },
  };
}

export function rwRandomGT(
  rng: RandomSource,
  label = 'kem',
): { readonly element: GTElement; readonly exponent: bigint } {
  const exponent = rng.scalar(`rw15:gt:${label}`);
  return { element: gtPow(RW15_EGG, exponent), exponent };
}

export function rwEncrypt(
  publicKeys: ReadonlyMap<string, RwAuthorityPublicKey>,
  lsss: RwLsss,
  message: GTElement,
  rng: RandomSource,
  nonce = '',
): { readonly ciphertext: RwCiphertext; readonly witness: RwEncryptionWitness } {
  const suffix = nonce === '' ? '' : `@${nonce}`;
  const z = rng.scalar(`rw15:encrypt:z${suffix}`);
  const v = [z];
  const w = [0n];
  for (let column = 2; column <= lsss.columns; column += 1) {
    v.push(rng.scalar(`rw15:encrypt:v:${column}${suffix}`));
    w.push(rng.scalar(`rw15:encrypt:w:${column}${suffix}`));
  }

  const witnesses = new Map<number, RwRowWitness>();
  const rows = lsss.rows.map((row): RwCiphertextRow => {
    const pk = publicKeys.get(row.authority);
    if (!pk) throw new Error(`RW15_PUBLIC_KEY_MISSING: ${row.authority}`);
    if (pk.id !== row.authority) {
      throw new Error(
        `RW15_PUBLIC_KEY_MISMATCH: map entry ${row.authority} contains key for ${pk.id}`,
      );
    }
    const tx = rng.scalar(`rw15:encrypt:tx:${row.index}${suffix}`);
    const lambda = dot(row.vector, v);
    const omega = dot(row.vector, w);
    witnesses.set(row.index, { tx, lambda, omega });
    return {
      rowIndex: row.index,
      attribute: row.attribute,
      authority: row.authority,
      C1: gtMul(gtPow(RW15_EGG, lambda), gtPow(pk.egga, tx)),
      C2: g1Pow(g1, mod(-tx)),
      C3: g1Mul(g1Pow(pk.gy, tx), g1Pow(g1, omega)),
      C4: g2Pow(rwHashAttribute(row.attribute), tx),
    };
  });

  return {
    ciphertext: { lsss, C0: gtMul(message, gtPow(RW15_EGG, z)), rows },
    witness: { z, v, w, rows: witnesses, message },
  };
}

/**
 * One raw row equation. `pairingGid` is explicit so tests can model the
 * strongest cross-user pooling attempt rather than relying on metadata checks.
 */
export function rwRowTerm(
  row: RwCiphertextRow,
  key: RwAttributeKey,
  pairingGid: string,
): GTElement {
  if (row.attribute !== key.attribute) {
    throw new Error(
      `RW15_KEY_ATTRIBUTE_MISMATCH: row ${row.rowIndex} needs ${row.attribute}, key has ${key.attribute}`,
    );
  }
  return gtMul(
    gtMul(row.C1, pairing(row.C2, key.K)),
    gtMul(pairing(row.C3, rwHashGid(pairingGid)), pairing(key.KPrime, row.C4)),
  );
}

export interface RwDecryptSuccess {
  readonly ok: true;
  readonly recovered: GTElement;
  readonly denominator: GTElement;
  readonly rowTerms: ReadonlyMap<number, GTElement>;
  readonly reconstruction: RwReconstruction;
  readonly pairings: number;
}

export interface RwDecryptFailure {
  readonly ok: false;
  readonly code: 'POLICY_UNSATISFIED';
  readonly reconstruction: RwReconstruction;
  readonly pairings: 0;
}

export type RwDecryptResult = RwDecryptSuccess | RwDecryptFailure;

export interface RwRawRowSelection {
  readonly rowIndex: number;
  readonly key: RwAttributeKey;
  /** Public H input selected by the adversarial combiner for this row. */
  readonly pairingGid: string;
}

function combine(
  ciphertext: RwCiphertext,
  reconstruction: RwReconstruction,
  selectionFor: (rowIndex: number) => RwRawRowSelection | undefined,
): RwDecryptSuccess {
  const before = pairingCount();
  const rowTerms = new Map<number, GTElement>();
  let denominator = gtPow(RW15_EGG, 0n);
  for (const rowIndex of reconstruction.usedRows) {
    const selection = selectionFor(rowIndex);
    if (!selection) throw new Error(`RW15_KEY_MISSING: no key selected for row ${rowIndex}`);
    const row = ciphertext.rows[rowIndex - 1];
    if (!row || row.rowIndex !== rowIndex) {
      throw new Error(`RW15_CIPHERTEXT: missing row ${rowIndex}`);
    }
    const term = rwRowTerm(row, selection.key, canonicalGid(selection.pairingGid));
    rowTerms.set(rowIndex, term);
    const coefficient = reconstruction.coefficients.get(rowIndex);
    if (coefficient === undefined) throw new Error(`RW15_LSSS: no coefficient for row ${rowIndex}`);
    denominator = gtMul(denominator, gtPow(term, coefficient));
  }
  return {
    ok: true,
    recovered: gtDiv(ciphertext.C0, denominator),
    denominator,
    rowTerms,
    reconstruction,
    pairings: pairingCount() - before,
  };
}

/** Standard paper interface: consume attribute keys issued to one exact GID. */
export function rwDecrypt(
  ciphertext: RwCiphertext,
  gidInput: string,
  keys: readonly RwAttributeKey[],
): RwDecryptResult {
  const gid = canonicalGid(gidInput);
  const coherent = keys.filter((key) => key.gid === gid);
  const keyByAttribute = new Map(coherent.map((key) => [key.attribute, key]));
  const reconstruction = reconstructRw(ciphertext.lsss, new Set(keyByAttribute.keys()));
  if (!reconstruction.satisfied) {
    return { ok: false, code: 'POLICY_UNSATISFIED', reconstruction, pairings: 0 };
  }
  return combine(ciphertext, reconstruction, (rowIndex) => {
    const row = ciphertext.rows[rowIndex - 1];
    const key = row ? keyByAttribute.get(row.attribute) : undefined;
    return key ? { rowIndex, key, pairingGid: gid } : undefined;
  });
}

/**
 * Adversarial combiner with no same-GID shortcut. Each selected row may use a
 * different public H input; RW15's zero sharing must still prevent pooling.
 */
export function rwRawDecrypt(
  ciphertext: RwCiphertext,
  selections: readonly RwRawRowSelection[],
): RwDecryptResult {
  const byRow = new Map(selections.map((selection) => [selection.rowIndex, selection]));
  const held = new Set(selections.map((selection) => selection.key.attribute));
  const reconstruction = reconstructRw(ciphertext.lsss, held);
  if (!reconstruction.satisfied) {
    return { ok: false, code: 'POLICY_UNSATISFIED', reconstruction, pairings: 0 };
  }
  return combine(ciphertext, reconstruction, (rowIndex) => byRow.get(rowIndex));
}
