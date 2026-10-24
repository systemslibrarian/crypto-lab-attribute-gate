/**
 * FABESA CP-A2BE, a bounded executable transcription of Figure 5 and section
 * 3.3 of Meng, Chen, Tian and Manulis, CCS 2024 (ePrint 2024/986).
 *
 * Paper equations, in multiplicative notation:
 *
 *   Setup:  pk = (g3, g2^b1, g2^b2, e(g1,g2)^alpha)
 *   KeyGen: sk1 = g2^r
 *           sk2 = g1^alpha g3^-r
 *           sk3,u = H(0||u)^(r/b1)
 *           sk4,u = H(1||u)^(r/b2)
 *   Enc:    ct1,i = g3^(Mi . (s||v)) H(0||pi(i))^s1 H(1||pi(i))^s2
 *           ct2 = g2^s; ct3 = g2^(b1 s1); ct4 = g2^(b2 s2)
 *           ct5 = e(g1,g2)^(alpha s) msg, where s = s1+s2
 *   Dec:    ct5 e(prod sk3^gamma,ct3)e(prod sk4^gamma,ct4)
 *           ---------------------------------------------------
 *             e(prod ct1^gamma,sk1)e(sk2,ct2)
 *
 * The paper's partially hidden payload intentionally exposes M, the row-to-name
 * map, dimensions, lengths, and key attribute names. Only attribute VALUES are
 * absent. This module preserves that boundary in its types: neither
 * PublicPolicy nor SecretKey contains a value string.
 *
 * Bounded teaching profile. The basic Figure 5 construction is used with one
 * value per public attribute name and no repeated names in a policy. Section
 * 3.4 points to a separate multi-use extension; this lab does not silently
 * claim that extension. Candidate search limits are exported below.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  G1_BYTES,
  G2_BYTES,
  addMod,
  divMod,
  g1,
  g1Mul,
  g1Pow,
  g1Product,
  g2,
  g2Pow,
  gtDiv,
  gtMul,
  gtPow,
  mod,
  mulMod,
  pairing,
  type G1Point,
  type G2Point,
  type GTElement,
} from '../fame/bls';
import type { RandomSource } from '../fame/rand';
import {
  encodeHiddenAttribute,
  validateHiddenAttribute,
  type HiddenAttribute,
} from './encoding';

export const FABESA_PAPER = 'https://eprint.iacr.org/2024/986';
export const FABESA_HASH_DST =
  'CRYPTO-LAB-ATTRIBUTE-GATE-FABESA-CP-A2BE-v1_XMD:SHA-256_SSWU_RO_';

/**
 * Theorem 4 is the paper's CP-A2BE anonymity theorem (ROM, DLIN). Section 2.3
 * formulates DLIN asymmetrically for the Type-III setting, in both G1 and G2.
 * It applies to the paper construction, not to this browser code's engineering
 * quality and not to the KEM/HKDF/AES-GCM teaching wrapper in kem.ts.
 */
export const FABESA_SECURITY_SCOPE = {
  construction: 'FABESA CP-A2BE, Figure 5 plus the partially hidden payload of section 3.3',
  theorem:
    'Theorem 4: adaptive anonymity in the random oracle model under the DLIN assumption; section 2.3 uses an asymmetric Type-III formulation in both G1 and G2',
  adaptation:
    'The bounded candidate search and KEM/HKDF/AES-GCM record wrapper are teaching adaptations; the theorem is not transferred to that composed browser demo.',
} as const;

export const MAX_POLICY_ROWS = 16;
export const MAX_POLICY_COLUMNS = 16;
export const MAX_MATCHED_ROWS = 10;
export const MAX_RECONSTRUCTION_CANDIDATES = 32;
/** Four pairing TERMS appear in Figure 5; identity short-circuits can execute fewer. */
export const FABESA_PAIRING_TERMS_PER_CANDIDATE = 4;

export interface HiddenPolicyRow extends HiddenAttribute {
  /** One row M_i of the monotone span program. */
  readonly vector: readonly bigint[];
}

export interface HiddenPolicy {
  readonly rows: readonly HiddenPolicyRow[];
}

export interface PublicPolicyRow {
  /** One-based, matching the paper's i. */
  readonly index: number;
  /** Public attribute category n_pi(i). */
  readonly name: string;
  readonly vector: readonly bigint[];
}

export interface PublicPolicy {
  readonly columns: number;
  readonly rows: readonly PublicPolicyRow[];
}

export interface PublicKey {
  readonly g3: G1Point;
  readonly B1: G2Point;
  readonly B2: G2Point;
  readonly EAlpha: GTElement;
}

export interface MasterSecretKey {
  readonly alpha: bigint;
  readonly b1: bigint;
  readonly b2: bigint;
}

export interface Authority {
  readonly pk: PublicKey;
  readonly msk: MasterSecretKey;
}

export interface KeyComponent {
  readonly sk3: G1Point;
  readonly sk4: G1Point;
}

export interface SecretKey {
  /** The only attribute metadata disclosed by the key payload. */
  readonly names: readonly string[];
  readonly sk1: G2Point;
  readonly sk2: G1Point;
  /** Public name -> hidden-value-dependent group elements. */
  readonly components: ReadonlyMap<string, KeyComponent>;
}

export interface Ciphertext {
  /** Public (M, pi, names); values are deliberately absent. */
  readonly policy: PublicPolicy;
  readonly ct1: readonly G1Point[];
  readonly ct2: G2Point;
  readonly ct3: G2Point;
  readonly ct4: G2Point;
  readonly ct5: GTElement;
}

export interface ReconstructionTerm {
  readonly rowIndex: number;
  readonly coefficient: bigint;
}

export interface ReconstructionCandidate {
  readonly terms: readonly ReconstructionTerm[];
}

export interface EnumerationLimits {
  readonly maxMatchedRows: number;
  readonly maxCandidates: number;
}

export const DEFAULT_ENUMERATION_LIMITS: EnumerationLimits = {
  maxMatchedRows: MAX_MATCHED_ROWS,
  maxCandidates: MAX_RECONSTRUCTION_CANDIDATES,
};

export type CandidateEnumeration =
  | {
      readonly ok: true;
      readonly candidates: readonly ReconstructionCandidate[];
      readonly matchedRows: readonly number[];
      readonly subsetsExamined: number;
    }
  | {
      readonly ok: false;
      readonly reason: 'MATCHED_ROW_BOUND_EXCEEDED' | 'CANDIDATE_BOUND_EXCEEDED';
      readonly matchedRows: readonly number[];
      readonly subsetsExamined: number;
      readonly limit: number;
    };

export class FabesaCiphertextError extends Error {
  readonly code = 'MALFORMED_CIPHERTEXT' as const;

  constructor(message: string) {
    super(`MALFORMED_CIPHERTEXT: ${message}`);
    this.name = 'FabesaCiphertextError';
  }
}

export class FabesaKeyError extends Error {
  readonly code = 'MALFORMED_SECRET_KEY' as const;

  constructor(message: string) {
    super(`MALFORMED_SECRET_KEY: ${message}`);
    this.name = 'FabesaKeyError';
  }
}

export function hashHiddenAttribute(branch: 0 | 1, attribute: HiddenAttribute): G1Point {
  return bls.G1.hashToCurve(encodeHiddenAttribute(branch, attribute), {
    DST: FABESA_HASH_DST,
  }) as G1Point;
}

function assertUniqueNames(attributes: readonly HiddenAttribute[], where: string): void {
  const seen = new Set<string>();
  for (const attribute of attributes) {
    validateHiddenAttribute(attribute);
    if (seen.has(attribute.name)) {
      throw new Error(
        `FABESA_PROFILE: ${where} repeats public name "${attribute.name}"; ` +
          'the section 3.4 multi-use extension is outside this bounded lesson',
      );
    }
    seen.add(attribute.name);
  }
}

export function validateHiddenPolicy(policy: HiddenPolicy): void {
  if (policy.rows.length === 0 || policy.rows.length > MAX_POLICY_ROWS) {
    throw new Error(`FABESA_POLICY: policy must have 1-${MAX_POLICY_ROWS} rows`);
  }
  assertUniqueNames(policy.rows, 'policy');
  const columns = policy.rows[0]?.vector.length ?? 0;
  if (columns === 0 || columns > MAX_POLICY_COLUMNS) {
    throw new Error(`FABESA_POLICY: matrix must have 1-${MAX_POLICY_COLUMNS} columns`);
  }
  for (const [index, row] of policy.rows.entries()) {
    if (row.vector.length !== columns) {
      throw new Error(
        `FABESA_POLICY: row ${index + 1} has ${row.vector.length} columns; expected ${columns}`,
      );
    }
  }
}

export function validatePublicPolicy(policy: PublicPolicy): void {
  if (policy.rows.length === 0 || policy.rows.length > MAX_POLICY_ROWS) {
    throw new Error(`FABESA_POLICY: public policy must have 1-${MAX_POLICY_ROWS} rows`);
  }
  if (!Number.isInteger(policy.columns) || policy.columns < 1 || policy.columns > MAX_POLICY_COLUMNS) {
    throw new Error(`FABESA_POLICY: public matrix must have 1-${MAX_POLICY_COLUMNS} columns`);
  }
  const names = new Set<string>();
  policy.rows.forEach((row, offset) => {
    validateHiddenAttribute({ name: row.name, value: '_' });
    if (row.index !== offset + 1) {
      throw new Error('FABESA_POLICY: public row indices must be consecutive and one-based');
    }
    if (row.vector.length !== policy.columns) {
      throw new Error(`FABESA_POLICY: public row ${row.index} has the wrong width`);
    }
    if (names.has(row.name)) {
      throw new Error(`FABESA_PROFILE: public policy repeats name "${row.name}"`);
    }
    names.add(row.name);
  });
}

export function setup(rng: RandomSource): Authority {
  // b1 and b2 must be non-zero because KeyGen divides by them. Figure 5 samples
  // alpha from all of Zp, while g3 must be a group generator/nonidentity.
  const alpha = rng.scalar('fabesa:alpha');
  const b1 = rng.nonZeroScalar('fabesa:b1');
  const b2 = rng.nonZeroScalar('fabesa:b2');
  const g3 = g1Pow(g1, rng.nonZeroScalar('fabesa:g3'));
  const e = pairing(g1, g2);
  return {
    pk: {
      g3,
      B1: g2Pow(g2, b1),
      B2: g2Pow(g2, b2),
      EAlpha: gtPow(e, alpha),
    },
    msk: { alpha, b1, b2 },
  };
}

export function keygen(
  pk: PublicKey,
  msk: MasterSecretKey,
  attributes: readonly HiddenAttribute[],
  rng: RandomSource,
  nonce = '',
): SecretKey {
  if (attributes.length === 0 || attributes.length > MAX_POLICY_ROWS) {
    throw new Error(`FABESA_KEY: key must contain 1-${MAX_POLICY_ROWS} attributes`);
  }
  assertUniqueNames(attributes, 'key attribute set');
  const tag = nonce === '' ? '' : `@${nonce}`;
  // Figure 5 samples r uniformly from all of Zp (including the negligible
  // r=0 case), so do not condition this draw merely to make prettier output.
  const r = rng.scalar(`fabesa:r${tag}`);
  const components = new Map<string, KeyComponent>();
  for (const attribute of attributes) {
    components.set(attribute.name, {
      sk3: g1Pow(hashHiddenAttribute(0, attribute), divMod(r, msk.b1)),
      sk4: g1Pow(hashHiddenAttribute(1, attribute), divMod(r, msk.b2)),
    });
  }
  return {
    names: attributes.map((attribute) => attribute.name),
    sk1: g2Pow(g2, r),
    sk2: g1Mul(g1Pow(g1, msk.alpha), g1Pow(pk.g3, mod(-r))),
    components,
  };
}

function dot(left: readonly bigint[], right: readonly bigint[]): bigint {
  return left.reduce((sum, value, index) => addMod(sum, mulMod(value, right[index])), 0n);
}

export function publicPolicyOf(policy: HiddenPolicy): PublicPolicy {
  validateHiddenPolicy(policy);
  return {
    columns: policy.rows[0].vector.length,
    rows: policy.rows.map((row, offset) => ({
      index: offset + 1,
      name: row.name,
      vector: row.vector.map(mod),
    })),
  };
}

export function encrypt(
  pk: PublicKey,
  policy: HiddenPolicy,
  message: GTElement,
  rng: RandomSource,
  nonce = '',
): Ciphertext {
  validateHiddenPolicy(policy);
  const tag = nonce === '' ? '' : `@${nonce}`;
  const s1 = rng.scalar(`fabesa:s1${tag}`);
  const s2 = rng.scalar(`fabesa:s2${tag}`);
  const s = addMod(s1, s2);
  const vector = [
    s,
    ...Array.from({ length: policy.rows[0].vector.length - 1 }, (_, index) =>
      rng.scalar(`fabesa:v${index + 2}${tag}`),
    ),
  ];

  const ct1 = policy.rows.map((row) => {
    const share = dot(row.vector, vector);
    return g1Product([
      g1Pow(pk.g3, share),
      g1Pow(hashHiddenAttribute(0, row), s1),
      g1Pow(hashHiddenAttribute(1, row), s2),
    ]);
  });

  return {
    policy: publicPolicyOf(policy),
    ct1,
    ct2: g2Pow(g2, s),
    ct3: g2Pow(pk.B1, s1),
    ct4: g2Pow(pk.B2, s2),
    ct5: gtMul(gtPow(pk.EAlpha, s), message),
  };
}

/** Runtime shape/curve validation for objects crossing an untyped UI boundary. */
export function validateCiphertext(ciphertext: Ciphertext): void {
  if (!ciphertext || typeof ciphertext !== 'object') {
    throw new FabesaCiphertextError('ciphertext is not an object');
  }
  try {
    validatePublicPolicy(ciphertext.policy);
  } catch (error) {
    throw new FabesaCiphertextError(
      `public policy is invalid (${error instanceof Error ? error.message : 'unknown error'})`,
    );
  }
  if (!Array.isArray(ciphertext.ct1) || ciphertext.ct1.length !== ciphertext.policy.rows.length) {
    throw new FabesaCiphertextError(
      `ct1 has ${Array.isArray(ciphertext.ct1) ? ciphertext.ct1.length : 'no'} rows; ` +
        `policy has ${ciphertext.policy.rows.length}`,
    );
  }
  try {
    ciphertext.ct1.forEach((point) => {
      point.assertValidity();
      if (point.toBytes(true).length !== G1_BYTES) throw new Error('ct1 contains a non-G1 point');
    });
    ciphertext.ct2.assertValidity();
    ciphertext.ct3.assertValidity();
    ciphertext.ct4.assertValidity();
    for (const point of [ciphertext.ct2, ciphertext.ct3, ciphertext.ct4]) {
      if (point.toBytes(true).length !== G2_BYTES) throw new Error('ct2/ct3/ct4 contains a non-G2 point');
    }
    if (ciphertext.ct5 === undefined || ciphertext.ct5 === null) {
      throw new Error('ct5 is absent');
    }
    gtPow(ciphertext.ct5, 1n);
  } catch (error) {
    throw new FabesaCiphertextError(
      `a required group component is absent or invalid (${error instanceof Error ? error.message : 'unknown error'})`,
    );
  }
}

export function validateSecretKey(key: SecretKey): void {
  if (!key || typeof key !== 'object') throw new FabesaKeyError('key is not an object');
  if (!Array.isArray(key.names) || key.names.length === 0 || key.names.length > MAX_POLICY_ROWS) {
    throw new FabesaKeyError(`names must contain 1-${MAX_POLICY_ROWS} public names`);
  }
  if (!(key.components instanceof Map)) {
    throw new FabesaKeyError('components is not a Map');
  }
  const seen = new Set<string>();
  try {
    for (const name of key.names) {
      validateHiddenAttribute({ name, value: '_' });
      if (seen.has(name)) throw new Error(`name "${name}" is repeated`);
      seen.add(name);
      if (!key.components.has(name)) throw new Error(`component for "${name}" is absent`);
    }
    for (const [name, component] of key.components) {
      if (!seen.has(name)) throw new Error(`component for undeclared name "${name}" is present`);
      component.sk3.assertValidity();
      component.sk4.assertValidity();
      if (
        component.sk3.toBytes(true).length !== G1_BYTES ||
        component.sk4.toBytes(true).length !== G1_BYTES
      ) {
        throw new Error(`component for "${name}" is not in G1`);
      }
    }
    key.sk1.assertValidity();
    key.sk2.assertValidity();
    if (key.sk1.toBytes(true).length !== G2_BYTES || key.sk2.toBytes(true).length !== G1_BYTES) {
      throw new Error('sk1/sk2 has the wrong source-group type');
    }
  } catch (error) {
    throw new FabesaKeyError(error instanceof Error ? error.message : 'unknown key error');
  }
}

/** Solve M_I^T gamma = (1, 0, ..., 0) with free variables fixed to zero. */
function solveReconstruction(
  rows: readonly PublicPolicyRow[],
  columns: number,
): bigint[] | null {
  const variables = rows.length;
  const augmented = Array.from({ length: columns }, (_, column) => [
    ...rows.map((row) => mod(row.vector[column])),
    column === 0 ? 1n : 0n,
  ]);
  const pivots: { equation: number; variable: number }[] = [];
  let equation = 0;

  for (let variable = 0; variable < variables && equation < columns; variable++) {
    let pivot = equation;
    while (pivot < columns && augmented[pivot][variable] === 0n) pivot += 1;
    if (pivot === columns) continue;
    [augmented[equation], augmented[pivot]] = [augmented[pivot], augmented[equation]];

    const inverse = divMod(1n, augmented[equation][variable]);
    augmented[equation] = augmented[equation].map((entry) => mulMod(entry, inverse));
    for (let other = 0; other < columns; other++) {
      if (other === equation) continue;
      const factor = augmented[other][variable];
      if (factor === 0n) continue;
      augmented[other] = augmented[other].map((entry, index) =>
        mod(entry - mulMod(factor, augmented[equation][index])),
      );
    }
    pivots.push({ equation, variable });
    equation += 1;
  }

  for (const row of augmented) {
    if (row.slice(0, variables).every((entry) => entry === 0n) && row[variables] !== 0n) {
      return null;
    }
  }

  const solution = new Array<bigint>(variables).fill(0n);
  for (const pivot of pivots) {
    solution[pivot.variable] = augmented[pivot.equation][variables];
  }
  return solution;
}

function combinations<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  const choose = (start: number, selected: T[]): void => {
    if (selected.length === size) {
      out.push(selected.slice());
      return;
    }
    const remaining = size - selected.length;
    for (let index = start; index <= items.length - remaining; index++) {
      selected.push(items[index]);
      choose(index + 1, selected);
      selected.pop();
    }
  };
  choose(0, []);
  return out;
}

function checkedLimits(overrides?: Partial<EnumerationLimits>): EnumerationLimits {
  const limits = { ...DEFAULT_ENUMERATION_LIMITS, ...overrides };
  if (
    !Number.isInteger(limits.maxMatchedRows) ||
    limits.maxMatchedRows < 1 ||
    limits.maxMatchedRows > MAX_MATCHED_ROWS
  ) {
    throw new Error(`FABESA_LIMIT: maxMatchedRows must be 1-${MAX_MATCHED_ROWS}`);
  }
  if (
    !Number.isInteger(limits.maxCandidates) ||
    limits.maxCandidates < 1 ||
    limits.maxCandidates > MAX_RECONSTRUCTION_CANDIDATES
  ) {
    throw new Error(
      `FABESA_LIMIT: maxCandidates must be 1-${MAX_RECONSTRUCTION_CANDIDATES}`,
    );
  }
  return limits;
}

/**
 * Enumerate all minimal-support public-name matches within explicit bounds.
 *
 * Attribute values are hidden, so public names can make more than one branch
 * look usable. The paper says to try satisfying subsets until a message is
 * recovered. The hybrid wrapper uses the AES-GCM tag as that recovery oracle.
 */
export function enumerateReconstructionCandidates(
  policy: PublicPolicy,
  key: SecretKey,
  overrides?: Partial<EnumerationLimits>,
): CandidateEnumeration {
  validatePublicPolicy(policy);
  validateSecretKey(key);
  const limits = checkedLimits(overrides);
  const matched = policy.rows.filter((row) => key.components.has(row.name));
  const matchedRows = matched.map((row) => row.index);
  if (matched.length > limits.maxMatchedRows) {
    return {
      ok: false,
      reason: 'MATCHED_ROW_BOUND_EXCEEDED',
      matchedRows,
      subsetsExamined: 0,
      limit: limits.maxMatchedRows,
    };
  }

  const candidates: ReconstructionCandidate[] = [];
  const seen = new Set<string>();
  let subsetsExamined = 0;
  for (let size = 1; size <= matched.length; size++) {
    for (const subset of combinations(matched, size)) {
      subsetsExamined += 1;
      const coefficients = solveReconstruction(subset, policy.columns);
      if (coefficients === null || coefficients.some((coefficient) => coefficient === 0n)) {
        continue;
      }
      const terms = subset.map((row, index) => ({
        rowIndex: row.index,
        coefficient: mod(coefficients[index]),
      }));
      const signature = terms
        .map((term) => `${term.rowIndex}:${term.coefficient.toString(16)}`)
        .join('|');
      if (seen.has(signature)) continue;
      seen.add(signature);
      if (candidates.length === limits.maxCandidates) {
        return {
          ok: false,
          reason: 'CANDIDATE_BOUND_EXCEEDED',
          matchedRows,
          subsetsExamined,
          limit: limits.maxCandidates,
        };
      }
      candidates.push({ terms });
    }
  }
  return { ok: true, candidates, matchedRows, subsetsExamined };
}

function assertCandidate(
  ciphertext: Ciphertext,
  key: SecretKey,
  candidate: ReconstructionCandidate,
): void {
  validateCiphertext(ciphertext);
  validateSecretKey(key);
  if (candidate.terms.length === 0) {
    throw new Error('FABESA_CANDIDATE: reconstruction is empty');
  }
  const combined = new Array<bigint>(ciphertext.policy.columns).fill(0n);
  const seen = new Set<number>();
  for (const term of candidate.terms) {
    if (!Number.isInteger(term.rowIndex) || term.rowIndex < 1 || term.rowIndex > ciphertext.policy.rows.length) {
      throw new Error('FABESA_CANDIDATE: row index is outside the policy');
    }
    if (seen.has(term.rowIndex) || mod(term.coefficient) === 0n) {
      throw new Error('FABESA_CANDIDATE: rows must be unique and coefficients non-zero');
    }
    seen.add(term.rowIndex);
    const row = ciphertext.policy.rows[term.rowIndex - 1];
    if (!key.components.has(row.name)) {
      throw new Error(`FABESA_CANDIDATE: key has no component for public name "${row.name}"`);
    }
    row.vector.forEach((entry, column) => {
      combined[column] = addMod(combined[column], mulMod(term.coefficient, entry));
    });
  }
  if (combined[0] !== 1n || combined.slice(1).some((entry) => entry !== 0n)) {
    throw new Error('FABESA_CANDIDATE: coefficients do not reconstruct (1,0,...,0)');
  }
}

/** Run Figure 5's four-pairing decryption equation for one public candidate. */
export function decryptCandidate(
  ciphertext: Ciphertext,
  key: SecretKey,
  candidate: ReconstructionCandidate,
): GTElement {
  assertCandidate(ciphertext, key, candidate);
  const keyedTerms = candidate.terms.map((term) => {
    const row = ciphertext.policy.rows[term.rowIndex - 1];
    const component = key.components.get(row.name);
    /* c8 ignore next -- assertCandidate checked the same lookup */
    if (!component) throw new Error('FABESA_CANDIDATE: component disappeared');
    return { term, component };
  });

  const ctProduct = g1Product(
    candidate.terms.map((term) => g1Pow(ciphertext.ct1[term.rowIndex - 1], term.coefficient)),
  );
  const sk3Product = g1Product(
    keyedTerms.map(({ term, component }) => g1Pow(component.sk3, term.coefficient)),
  );
  const sk4Product = g1Product(
    keyedTerms.map(({ term, component }) => g1Pow(component.sk4, term.coefficient)),
  );

  const numerator = gtMul(
    ciphertext.ct5,
    gtMul(pairing(sk3Product, ciphertext.ct3), pairing(sk4Product, ciphertext.ct4)),
  );
  const denominator = gtMul(pairing(ctProduct, key.sk1), pairing(key.sk2, ciphertext.ct2));
  return gtDiv(numerator, denominator);
}
