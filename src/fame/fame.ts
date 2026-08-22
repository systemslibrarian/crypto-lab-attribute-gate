/**
 * FAME -- Fast Attribute-based Message Encryption (Agrawal & Chase, CCS 2017).
 *
 * Ciphertext-policy ABE over a Type-3 pairing, transcribed from Figure 3.1 of
 * https://eprint.iacr.org/2017/807 with the linear-assumption parameter fixed
 * at k = 2 (the paper's main scheme). Every line below maps to a line of the
 * figure; the field and curve arithmetic comes from @noble/curves, the scheme
 * does not.
 *
 *   Setup   pk  = (h, H1 = h^a1, H2 = h^a2, T1 = e(g,h)^(d1 a1 + d3),
 *                                            T2 = e(g,h)^(d2 a2 + d3))
 *           msk = (g, h, a1, a2, b1, b2, g^d1, g^d2, g^d3)
 *
 *   KeyGen  sk0   = (h^(b1 r1), h^(b2 r2), h^(r1 + r2))
 *           sk_yt = H(y1t)^(b1 r1/at) H(y2t)^(b2 r2/at) H(y3t)^((r1+r2)/at) g^(sigma_y/at)
 *           sk_y  = (sk_y1, sk_y2, g^-sigma_y)
 *           sk'_t = g^dt H(011t)^(b1 r1/at) H(012t)^(b2 r2/at) H(013t)^((r1+r2)/at) g^(sigma'/at)
 *           sk'   = (sk'_1, sk'_2, g^d3 g^-sigma')
 *
 *   Encrypt ct0   = (H1^s1, H2^s2, h^(s1+s2))
 *           ct_il = H(pi(i) l 1)^s1 H(pi(i) l 2)^s2
 *                     prod_j (H(0 j l 1)^s1 H(0 j l 2)^s2)^M_ij
 *           ct'   = T1^s1 T2^s2 msg
 *
 *   Decrypt num = ct' prod_l e(prod_i ct_il^gamma_i, sk0_l)
 *           den = prod_l e(sk'_l prod_i sk_pi(i)l^gamma_i, ct0_l)
 *           msg = num / den
 *
 * WHY FAME AND NOT BSW07. Bethencourt-Sahai-Waters (IEEE S&P 2007) is the
 * access-tree construction everyone cites, and it assumes a SYMMETRIC pairing
 * e : G0 x G0 -> GT. BLS12-381 is Type-3: e : G1 x G2 -> GT with no efficient
 * isomorphism either way, and several BSW elements are needed on both the key
 * and the ciphertext side. Moving BSW here would require a translation
 * argument for every such element. FAME was designed for Type-3 from the
 * start, so there is nothing to translate. The collusion property this lab is
 * built around -- fresh per-user randomness that does not cancel across keys --
 * is identical in both schemes. The page states this in the Construction
 * disclosure; the derivation of the residual is in predictedResidual below.
 */
import {
  G1_IDENTITY,
  L_INDICES,
  T_INDICES,
  addMod,
  divMod,
  g1,
  g1Inv,
  g1Mul,
  g1Pow,
  g1Product,
  g2,
  g2Pow,
  gtDiv,
  gtMul,
  gtPow,
  gtProduct,
  hashAttribute,
  hashColumn,
  mod,
  mulMod,
  pairing,
  type G1Point,
  type G2Point,
  type GTElement,
} from './bls';
import type { RandomSource } from './rand';
import type { Msp } from './msp';
import { reconstruct, type Reconstruction } from './msp';
import type { PolicyNode } from './policy';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export interface PublicKey {
  readonly h: G2Point;
  readonly H1: G2Point;
  readonly H2: G2Point;
  readonly T1: GTElement;
  readonly T2: GTElement;
}

export interface MasterSecretKey {
  readonly g: G1Point;
  readonly h: G2Point;
  /** (a1, a2). */
  readonly a: readonly [bigint, bigint];
  /** (b1, b2). */
  readonly b: readonly [bigint, bigint];
  /** (g^d1, g^d2, g^d3). The paper keeps d only in the exponent. */
  readonly gd: readonly [G1Point, G1Point, G1Point];
}

export interface Authority {
  readonly pk: PublicKey;
  readonly msk: MasterSecretKey;
}

/** Triple of G1 elements, the shape of every key component. */
export type G1Triple = readonly [G1Point, G1Point, G1Point];

export interface SecretKey {
  /** Indexed labels this key covers, e.g. `Doctor:1`. */
  readonly labels: readonly string[];
  readonly sk0: readonly [G2Point, G2Point, G2Point];
  /** label -> (sk_y1, sk_y2, g^-sigma_y). */
  readonly sk: ReadonlyMap<string, G1Triple>;
  readonly skPrime: G1Triple;
}

/**
 * Demo-only bookkeeping the authority would normally throw away.
 *
 * NOT part of the key in Figure 3.1. `decrypt` cannot see it -- it takes a
 * `SecretKey`, and this lives beside one. It exists so the collusion exhibit
 * can predict the leftover blinding factor from the r values directly, and
 * compare that prediction against what decryption actually produced.
 */
export interface KeyWitness {
  readonly r1: bigint;
  readonly r2: bigint;
  /** Br = (b1 r1, b2 r2, r1 + r2). The per-user randomization, in the exponent. */
  readonly Br: readonly [bigint, bigint, bigint];
  readonly sigmaPrime: bigint;
  readonly sigma: ReadonlyMap<string, bigint>;
}

export interface IssuedKey {
  readonly holder: string;
  /** Attribute names as issued, before indexing. */
  readonly heldNames: readonly string[];
  readonly key: SecretKey;
  readonly witness: KeyWitness;
  /** The registry k each held name was expanded to when this key was minted. */
  readonly copiesAtIssue: ReadonlyMap<string, number>;
}

export interface Ciphertext {
  readonly policy: PolicyNode;
  readonly msp: Msp;
  readonly ct0: readonly [G2Point, G2Point, G2Point];
  /** ct_i for each MSP row, in row order. */
  readonly ct: readonly G1Triple[];
  readonly ctPrime: GTElement;
}

/** What the encryptor knows and the decryptor does not. Demo bookkeeping only. */
export interface CiphertextWitness {
  readonly s1: bigint;
  readonly s2: bigint;
  /** The GT element that was encapsulated. */
  readonly encapsulated: GTElement;
}

/* -------------------------------------------------------------------------- */
/* Setup                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Setup(1^lambda).
 *
 * g and h are the standard BLS12-381 base points rather than fresh random
 * generators. Both are public and any generator works; fixing them makes the
 * pinned vectors reproducible in a second implementation.
 */
export function setup(rng: RandomSource): Authority {
  const a1 = rng.nonZeroScalar('a1');
  const a2 = rng.nonZeroScalar('a2');
  const b1 = rng.nonZeroScalar('b1');
  const b2 = rng.nonZeroScalar('b2');
  const d1 = rng.scalar('d1');
  const d2 = rng.scalar('d2');
  const d3 = rng.scalar('d3');

  const egh = pairing(g1, g2);
  const pk: PublicKey = {
    h: g2,
    H1: g2Pow(g2, a1),
    H2: g2Pow(g2, a2),
    T1: gtPow(egh, addMod(mulMod(d1, a1), d3)),
    T2: gtPow(egh, addMod(mulMod(d2, a2), d3)),
  };
  const msk: MasterSecretKey = {
    g: g1,
    h: g2,
    a: [a1, a2],
    b: [b1, b2],
    gd: [g1Pow(g1, d1), g1Pow(g1, d2), g1Pow(g1, d3)],
  };
  return { pk, msk };
}

/* -------------------------------------------------------------------------- */
/* KeyGen                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * KeyGen(msk, S). `labels` are the indexed labels from the one-use transform.
 *
 * The whole collusion story lives in r1 and r2: they are drawn fresh per call,
 * so two keys issued to two people carry different Br in every component.
 */
export function keygen(
  msk: MasterSecretKey,
  labels: readonly string[],
  rng: RandomSource,
  nonce = '',
): { key: SecretKey; witness: KeyWitness } {
  const tag = nonce === '' ? '' : `@${nonce}`;
  const r1 = rng.scalar(`r1${tag}`);
  const r2 = rng.scalar(`r2${tag}`);
  const [b1, b2] = msk.b;
  const Br: readonly [bigint, bigint, bigint] = [
    mulMod(b1, r1),
    mulMod(b2, r2),
    addMod(r1, r2),
  ];

  const sk0: readonly [G2Point, G2Point, G2Point] = [
    g2Pow(msk.h, Br[0]),
    g2Pow(msk.h, Br[1]),
    g2Pow(msk.h, Br[2]),
  ];

  const sk = new Map<string, G1Triple>();
  const sigma = new Map<string, bigint>();
  for (const y of labels) {
    if (sk.has(y)) continue; // a key holds one component per label
    const sy = rng.scalar(`sigma:${y}${tag}`);
    sigma.set(y, sy);
    const parts = T_INDICES.map((t) => {
      const at = msk.a[t - 1];
      const factors = L_INDICES.map((l) => g1Pow(hashAttribute(y, l, t), divMod(Br[l - 1], at)));
      return g1Mul(g1Product(factors), g1Pow(msk.g, divMod(sy, at)));
    });
    sk.set(y, [parts[0], parts[1], g1Pow(g1Inv(msk.g), sy)]);
  }

  const sigmaPrime = rng.scalar(`sigmaPrime${tag}`);
  const primeParts = T_INDICES.map((t) => {
    const at = msk.a[t - 1];
    const factors = L_INDICES.map((l) => g1Pow(hashColumn(1, l, t), divMod(Br[l - 1], at)));
    return g1Mul(
      g1Mul(msk.gd[t - 1], g1Product(factors)),
      g1Pow(msk.g, divMod(sigmaPrime, at)),
    );
  });
  const skPrime: G1Triple = [
    primeParts[0],
    primeParts[1],
    g1Mul(msk.gd[2], g1Pow(g1Inv(msk.g), sigmaPrime)),
  ];

  return {
    key: { labels: [...sk.keys()], sk0, sk, skPrime },
    witness: { r1, r2, Br, sigmaPrime, sigma },
  };
}

/* -------------------------------------------------------------------------- */
/* Encrypt                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Encrypt(pk, (M, pi), msg) with msg in GT.
 *
 * The message space really is a single GT element. Application data does not
 * fit here and must not be forced to; kem.ts wraps this as a KEM, which is
 * what the paper recommends.
 */
export function encrypt(
  pk: PublicKey,
  policy: PolicyNode,
  msp: Msp,
  message: GTElement,
  rng: RandomSource,
  nonce = '',
): { ciphertext: Ciphertext; witness: CiphertextWitness } {
  const tag = nonce === '' ? '' : `@${nonce}`;
  const s1 = rng.scalar(`s1${tag}`);
  const s2 = rng.scalar(`s2${tag}`);
  const s: readonly [bigint, bigint] = [s1, s2];

  const ct0: readonly [G2Point, G2Point, G2Point] = [
    g2Pow(pk.H1, s1),
    g2Pow(pk.H2, s2),
    g2Pow(pk.h, addMod(s1, s2)),
  ];

  const ct: G1Triple[] = msp.rows.map((row) => {
    const triple = L_INDICES.map((l) => {
      const perT = T_INDICES.map((t) => {
        let acc = hashAttribute(row.label, l, t);
        for (let j = 1; j <= msp.columns; j++) {
          const m = row.vector[j - 1];
          if (m === 0n) continue;
          acc = g1Mul(acc, g1Pow(hashColumn(j, l, t), m));
        }
        return g1Pow(acc, s[t - 1]);
      });
      return g1Mul(perT[0], perT[1]);
    });
    return [triple[0], triple[1], triple[2]] as G1Triple;
  });

  const ctPrime = gtMul(gtMul(gtPow(pk.T1, s1), gtPow(pk.T2, s2)), message);

  return {
    ciphertext: { policy, msp, ct0, ct, ctPrime },
    witness: { s1, s2, encapsulated: message },
  };
}

/* -------------------------------------------------------------------------- */
/* Decrypt                                                                    */
/* -------------------------------------------------------------------------- */

export interface DecryptSuccess {
  readonly ok: true;
  /** num / den. Equal to the encapsulated element iff the key is coherent. */
  readonly recovered: GTElement;
  readonly reconstruction: Reconstruction;
  readonly num: GTElement;
  readonly den: GTElement;
}

export interface DecryptFailure {
  readonly ok: false;
  readonly code: 'POLICY_UNSATISFIED';
  readonly reconstruction: Reconstruction;
  /** Rows whose attribute the key does not hold, in row order. */
  readonly unsatisfiedRows: readonly number[];
  /** A one-line reason naming the actual cause. */
  readonly detail: string;
}

export type DecryptResult = DecryptSuccess | DecryptFailure;

/**
 * Decrypt(pk, ct, sk).
 *
 * Nothing here inspects who the key belongs to, and there is no coherence
 * check. A key spliced from two people runs down exactly this path and
 * produces a GT element; it is simply the wrong one.
 */
export function decrypt(ct: Ciphertext, sk: SecretKey): DecryptResult {
  const held = new Set(sk.labels);
  const rec = reconstruct(ct.policy, ct.msp, held);

  if (!rec.satisfied) {
    const missing = ct.msp.rows.filter((r) => !held.has(r.label));
    const unsatisfiedRows = missing.map((r) => r.index);
    const gate = [...rec.status.entries()].find(
      ([, s]) => !s.satisfied && s.reason === 'THRESHOLD_NOT_MET',
    );
    // Name BOTH causes. A gate shortfall says how the policy failed; the row
    // labels say which attributes would have fixed it, and after the one-use
    // transform those labels are indexed, so "Doctor:2" is genuinely different
    // information from "Doctor".
    const parts: string[] = [];
    if (gate && !gate[1].satisfied && gate[1].reason === 'THRESHOLD_NOT_MET') {
      parts.push(
        `THRESHOLD_NOT_MET: a gate needed ${gate[1].need} satisfied inputs and had ${gate[1].have}`,
      );
    }
    if (missing.length > 0) {
      parts.push(
        `ATTR_MISSING: ${missing.map((r) => `row ${r.index} wants ${r.label}`).join(', ')}`,
      );
    }
    const detail = parts.join(' \u00b7 ');
    return { ok: false, code: 'POLICY_UNSATISFIED', reconstruction: rec, unsatisfiedRows, detail };
  }

  const rowByIndex = new Map(ct.msp.rows.map((r) => [r.index, r]));

  // num = ct' * prod_l e( prod_i ct_il^gamma_i , sk0_l )
  const numFactors = L_INDICES.map((l) => {
    const acc = g1Product(
      rec.usedRows.map((i) => {
        const gamma = rec.coefficients.get(i) as bigint;
        return g1Pow(ct.ct[i - 1][l - 1], gamma);
      }),
    );
    return pairing(acc, sk.sk0[l - 1]);
  });
  const num = gtMul(ct.ctPrime, gtProduct(numFactors));

  // den = prod_l e( sk'_l * prod_i sk_pi(i)l^gamma_i , ct0_l )
  const denFactors = L_INDICES.map((l) => {
    let acc = sk.skPrime[l - 1];
    for (const i of rec.usedRows) {
      const gamma = rec.coefficients.get(i) as bigint;
      const label = (rowByIndex.get(i) as { label: string }).label;
      const component = sk.sk.get(label);
      /* c8 ignore next -- rec.satisfied guarantees every used row is held */
      if (!component) return pairing(G1_IDENTITY, ct.ct0[l - 1]);
      acc = g1Mul(acc, g1Pow(component[l - 1], gamma));
    }
    return pairing(acc, ct.ct0[l - 1]);
  });
  const den = gtProduct(denFactors);

  return { ok: true, recovered: gtDiv(num, den), reconstruction: rec, num, den };
}

/* -------------------------------------------------------------------------- */
/* The residual -- why a pooled key fails, computed independently             */
/* -------------------------------------------------------------------------- */

/**
 * The leftover blinding factor, predicted from the r values alone.
 *
 * Working the exponents through gives, for a key
 * whose sk0/sk' come from user A and whose component for row i came from
 * user o(i):
 *
 *   recovered / message = prod_i prod_{l,t}
 *        e( H(pi(i), l, t), h ) ^ ( gamma_i * s_t * (Br^A_l - Br^o(i)_l) )
 *
 * Every factor with o(i) = A vanishes, so a coherent key leaves exactly 1 and
 * decryption is correct. A key spliced across two people leaves the terms
 * belonging to the borrowed rows, and they do not cancel because r is drawn
 * fresh for every key. That is collusion resistance, as an equation.
 *
 * This is a genuine second route to the answer: it never calls `decrypt`, and
 * it uses the r and s values rather than the group elements decryption pairs.
 * The exhibit compares the two.
 */
export function predictedResidual(
  ct: Ciphertext,
  rec: Reconstruction,
  baseWitness: KeyWitness,
  witnessForRow: (rowIndex: number) => KeyWitness,
  ctWitness: CiphertextWitness,
): GTElement {
  const rowByIndex = new Map(ct.msp.rows.map((r) => [r.index, r]));
  const s: readonly [bigint, bigint] = [ctWitness.s1, ctWitness.s2];
  const factors: GTElement[] = [];

  for (const i of rec.usedRows) {
    const gamma = rec.coefficients.get(i) as bigint;
    const other = witnessForRow(i);
    const label = (rowByIndex.get(i) as { label: string }).label;
    for (const l of L_INDICES) {
      const delta = mod(baseWitness.Br[l - 1] - other.Br[l - 1]);
      if (delta === 0n) continue;
      for (const t of T_INDICES) {
        const exponent = mulMod(mulMod(gamma, s[t - 1]), delta);
        if (exponent === 0n) continue;
        factors.push(gtPow(pairing(hashAttribute(label, l, t), g2), exponent));
      }
    }
  }
  return gtProduct(factors);
}

/**
 * A random element of GT, as e(g,h)^u.
 *
 * GT is the order-p subgroup of Fp12*, so "random bytes" is not a GT element.
 * Exponentiating the pairing of the generators is the standard way to sample
 * one, and it is what the KEM encapsulates.
 */
export function randomGT(rng: RandomSource, label = 'kem'): { element: GTElement; exponent: bigint } {
  const u = rng.scalar(`gt:${label}`);
  return { element: gtPow(pairing(g1, g2), u), exponent: u };
}
