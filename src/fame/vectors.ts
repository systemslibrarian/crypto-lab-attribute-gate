/**
 * Pinned known-answer vectors for this lab's FAME instantiation.
 *
 * No official FAME vectors exist: the paper publishes none and the authors'
 * Charm implementation pins none. So this lab pins its own, and pins them in
 * full -- every intermediate group element, each tagged with the group it
 * lives in.
 *
 * The tags are the point. Revision 1 of this lab's plan called for BSW07 over
 * BLS12-381, which cannot be done because BSW07 needs the same element on both
 * sides of a symmetric pairing and BLS12-381 is Type-3. Writing G1 or G2 next
 * to every element is how that class of mistake stays visible: if a value ever
 * needs to appear under both tags, the construction is wrong for this curve.
 *
 * vectors.test.ts does two separate things with this file:
 *   1. regenerates it from the seed and compares byte for byte, so any change
 *      to the scheme, the hash encoding or the MSP conversion shows up;
 *   2. re-derives the FAME correctness equations from the pinned scalars and
 *      group elements using nothing but the pairing and field helpers -- never
 *      calling setup, keygen, encrypt or decrypt. A test that re-runs the same
 *      code it is checking agrees with its own bugs.
 */
import {
  HASH_DST,
  L_INDICES,
  ORDER,
  T_INDICES,
  gtToHex,
  scalarToHex,
  tagG1,
  tagG2,
  tagGT,
  tagZp,
  type TaggedElement,
} from './bls';
import { seededRandom } from './rand';
import { and, attr, or, threshold, formatPolicy, type PolicyNode } from './policy';
import { policyToMsp, reconstruct, type Msp } from './msp';
import { decrypt, encrypt, keygen, randomGT, setup, type IssuedKey } from './fame';
import { analyseCollusion, poolKeys } from './collusion';
import { AttributeRegistry } from './oneuse';
import { deriveAesKey, sealRecord, toHex } from './kem';

/** Fixed seed. Changing it changes every vector, so it is part of the fixture. */
export const VECTOR_SEED = 'crypto-lab-attribute-gate/vectors/v1';

/** The record the KEM vector seals. Not sensitive; it is a fixture. */
export const VECTOR_RECORD =
  'MRN 00-4417 | Ward 3B | Troponin I 0.42 ng/mL | ECG: ST elevation, leads V2-V4';

/**
 * The vector policy: `(Doctor AND Cardiology) OR (Doctor AND Emergency)`.
 *
 * Chosen because it reuses `Doctor`, so the one-use transform is exercised by
 * the fixture rather than only by a unit test. Node ids are fixed so the MSP
 * row order is stable across runs.
 */
export function vectorPolicy(): PolicyNode {
  return or(
    [
      and([attr('Doctor', 'L1'), attr('Cardiology', 'L2')], 'G1'),
      and([attr('Doctor', 'L3'), attr('Emergency', 'L4')], 'G2'),
    ],
    'ROOT',
  );
}

/** A second policy with a real threshold gate, so Lagrange is pinned too. */
export function vectorThresholdPolicy(): PolicyNode {
  return threshold(
    2,
    [attr('Doctor', 'T1'), attr('Cardiology', 'T2'), attr('OnCall', 'T3')],
    'TGATE',
  );
}

export interface VectorHolder {
  readonly holder: string;
  readonly heldNames: readonly string[];
  readonly labels: readonly string[];
  readonly r1: TaggedElement;
  readonly r2: TaggedElement;
  readonly Br: readonly TaggedElement[];
  readonly sigmaPrime: TaggedElement;
  readonly sigma: Record<string, TaggedElement>;
  readonly sk0: readonly TaggedElement[];
  readonly sk: Record<string, readonly TaggedElement[]>;
  readonly skPrime: readonly TaggedElement[];
  readonly keyElements: number;
}

export interface VectorDecryption {
  readonly holder: string;
  readonly satisfied: boolean;
  readonly failureCode: string | null;
  readonly coefficients: readonly { readonly row: number; readonly gamma: TaggedElement }[];
  readonly recovered: TaggedElement | null;
  readonly matchesMessage: boolean;
}

export interface VectorFixture {
  readonly meta: Record<string, string | number>;
  readonly policy: {
    readonly expression: string;
    readonly reusedNames: readonly string[];
    readonly transform: readonly { readonly name: string; readonly labels: readonly string[] }[];
    readonly registry: readonly { readonly name: string; readonly copies: number }[];
  };
  readonly msp: {
    readonly columns: number;
    readonly rows: readonly {
      readonly index: number;
      readonly name: string;
      readonly label: string;
      readonly vector: readonly string[];
    }[];
  };
  readonly publicKey: Record<string, TaggedElement>;
  readonly masterSecret: Record<string, TaggedElement>;
  readonly keys: readonly VectorHolder[];
  readonly ciphertext: {
    readonly s1: TaggedElement;
    readonly s2: TaggedElement;
    readonly messageExponent: TaggedElement;
    readonly message: TaggedElement;
    readonly ct0: readonly TaggedElement[];
    readonly rows: readonly {
      readonly index: number;
      readonly label: string;
      readonly ct: readonly TaggedElement[];
    }[];
    readonly ctPrime: TaggedElement;
  };
  readonly decryptions: readonly VectorDecryption[];
  readonly collusion: {
    readonly base: string;
    readonly other: string;
    readonly provenance: readonly { readonly label: string; readonly holder: string }[];
    readonly satisfiedPolicy: boolean;
    readonly recovered: TaggedElement;
    readonly residual: TaggedElement;
    readonly residualIsOne: boolean;
    readonly routesAgree: boolean;
  };
  readonly threshold: {
    readonly expression: string;
    readonly columns: number;
    readonly rows: readonly { readonly label: string; readonly vector: readonly string[] }[];
    readonly heldBy: readonly string[];
    readonly lagrange: readonly { readonly points: readonly number[]; readonly basis: readonly string[] }[];
    readonly coefficients: readonly { readonly row: number; readonly gamma: TaggedElement }[];
    readonly recovered: TaggedElement;
    readonly matchesMessage: boolean;
  };
  readonly kem: {
    readonly hkdfInfo: string;
    readonly hkdfSalt: string;
    readonly aesKey: string;
    readonly nonce: string;
    readonly aad: string;
    readonly sealed: string;
  };
}

const CAST: { holder: string; has: string[] }[] = [
  { holder: 'Alice', has: ['Doctor', 'Cardiology'] },
  { holder: 'Bob', has: ['Doctor'] },
  { holder: 'Carol', has: ['Emergency'] },
  { holder: 'Dan', has: ['Nurse'] },
  { holder: 'Eve', has: ['Cardiology'] },
];

function mspRows(msp: Msp) {
  return msp.rows.map((r) => ({
    index: r.index,
    name: r.name,
    label: r.label,
    vector: r.vector.map((x) => scalarToHex(x)),
  }));
}

/** Build the whole fixture from the pinned seed. Deterministic by construction. */
export async function buildVectorFixture(): Promise<VectorFixture> {
  const rng = seededRandom(VECTOR_SEED);
  const { pk, msk } = setup(rng);

  const policy = vectorPolicy();
  const msp = policyToMsp(policy);

  const registry = new AttributeRegistry();
  registry.observePolicy(policy);
  // Carol and Dan hold attributes this policy never mentions; the registry
  // still needs an entry so their keys can be issued.
  for (const name of ['Emergency', 'Nurse', 'OnCall']) registry.observePolicy(attr(name));

  const issued: IssuedKey[] = CAST.map(({ holder, has }) => {
    const labels = registry.expand(has);
    const { key, witness } = keygen(msk, labels, rng, holder);
    const copiesAtIssue = new Map(has.map((n) => [n, registry.copies(n)]));
    return { holder, heldNames: has, key, witness, copiesAtIssue };
  });

  const { element: message, exponent: messageExponent } = randomGT(rng, 'vector');
  const { ciphertext, witness: ctWitness } = encrypt(pk, policy, msp, message, rng, 'vector');

  const decryptions: VectorDecryption[] = issued.map((u) => {
    const r = decrypt(ciphertext, u.key);
    return {
      holder: u.holder,
      satisfied: r.ok,
      failureCode: r.ok ? null : r.code,
      coefficients: r.ok
        ? r.reconstruction.usedRows.map((row) => ({
            row,
            gamma: tagZp(r.reconstruction.coefficients.get(row) as bigint),
          }))
        : [],
      recovered: r.ok ? tagGT(r.recovered) : null,
      matchesMessage: r.ok ? gtToHex(r.recovered) === gtToHex(message) : false,
    };
  });

  const bob = issued.find((u) => u.holder === 'Bob') as IssuedKey;
  const eve = issued.find((u) => u.holder === 'Eve') as IssuedKey;
  const pooled = poolKeys(bob, eve);
  const analysis = analyseCollusion(
    ciphertext,
    pooled,
    new Map([
      ['Bob', bob.witness],
      ['Eve', eve.witness],
    ]),
    ctWitness,
  );

  // Threshold vector: a separate ciphertext under a 2-of-3 gate.
  const tPolicy = vectorThresholdPolicy();
  const tMsp = policyToMsp(tPolicy);
  const { element: tMessage } = randomGT(rng, 'threshold');
  const { ciphertext: tCt } = encrypt(pk, tPolicy, tMsp, tMessage, rng, 'threshold');
  const tHeld = ['Doctor:1', 'OnCall:1'];
  const { key: tKey } = keygen(msk, tHeld, rng, 'ThresholdHolder');
  const tResult = decrypt(tCt, tKey);
  const tRec = reconstruct(tPolicy, tMsp, new Set(tHeld));

  // KEM vector: the record actually sealed under the recovered element.
  const aad = formatPolicy(policy);
  const sealed = await sealRecord(message, VECTOR_RECORD, aad, rng, 'vector-gcm');
  const { rawKey } = await deriveAesKey(message);

  return {
    meta: {
      scheme: 'FAME CP-ABE (Agrawal & Chase, CCS 2017), Figure 3.1, k = 2',
      paper: 'https://eprint.iacr.org/2017/807',
      curve: 'BLS12-381',
      pairing: 'Type-3, e: G1 x G2 -> GT',
      hashToCurve: HASH_DST,
      groupOrder: `0x${ORDER.toString(16)}`,
      seed: VECTOR_SEED,
      note:
        'Generated by src/fame/vectors.ts from the seed above. Every element is tagged ' +
        'with its group. vectors.test.ts re-derives the correctness equations from these ' +
        'values without calling setup, keygen, encrypt or decrypt.',
    },
    policy: {
      expression: formatPolicy(policy),
      reusedNames: msp.transform.reusedNames,
      transform: msp.transform.records.map((r) => ({ name: r.name, labels: r.labels })),
      registry: registry.names().map((name) => ({ name, copies: registry.copies(name) })),
    },
    msp: { columns: msp.columns, rows: mspRows(msp) },
    publicKey: {
      h: tagG2(pk.h),
      H1: tagG2(pk.H1),
      H2: tagG2(pk.H2),
      T1: tagGT(pk.T1),
      T2: tagGT(pk.T2),
    },
    masterSecret: {
      a1: tagZp(msk.a[0]),
      a2: tagZp(msk.a[1]),
      b1: tagZp(msk.b[0]),
      b2: tagZp(msk.b[1]),
      gd1: tagG1(msk.gd[0]),
      gd2: tagG1(msk.gd[1]),
      gd3: tagG1(msk.gd[2]),
    },
    keys: issued.map((u) => ({
      holder: u.holder,
      heldNames: u.heldNames,
      labels: u.key.labels,
      r1: tagZp(u.witness.r1),
      r2: tagZp(u.witness.r2),
      Br: u.witness.Br.map(tagZp),
      sigmaPrime: tagZp(u.witness.sigmaPrime),
      sigma: Object.fromEntries([...u.witness.sigma].map(([k, v]) => [k, tagZp(v)])),
      sk0: u.key.sk0.map(tagG2),
      sk: Object.fromEntries([...u.key.sk].map(([k, v]) => [k, v.map(tagG1)])),
      skPrime: u.key.skPrime.map(tagG1),
      // 3 elements of sk0 (G2) + 3 per attribute (G1) + 3 for sk' (G1).
      keyElements: 3 + 3 * u.key.sk.size + 3,
    })),
    ciphertext: {
      s1: tagZp(ctWitness.s1),
      s2: tagZp(ctWitness.s2),
      messageExponent: tagZp(messageExponent),
      message: tagGT(message),
      ct0: ciphertext.ct0.map(tagG2),
      rows: ciphertext.ct.map((row, i) => ({
        index: msp.rows[i].index,
        label: msp.rows[i].label,
        ct: row.map(tagG1),
      })),
      ctPrime: tagGT(ciphertext.ctPrime),
    },
    decryptions,
    collusion: {
      base: pooled.baseHolder,
      other: pooled.otherHolder,
      provenance: [...pooled.provenance].map(([label, holder]) => ({ label, holder })),
      satisfiedPolicy: analysis.satisfiedPolicy,
      recovered: tagGT(analysis.recovered as never),
      residual: tagGT(analysis.residualObserved as never),
      residualIsOne: analysis.residualIsOne,
      routesAgree: analysis.routesAgree,
    },
    threshold: {
      expression: formatPolicy(tPolicy),
      columns: tMsp.columns,
      rows: tMsp.rows.map((r) => ({ label: r.label, vector: r.vector.map(scalarToHex) })),
      heldBy: tHeld,
      lagrange: tRec.lagrangeSteps.map((s) => ({
        points: s.points,
        basis: s.basis.map(scalarToHex),
      })),
      coefficients: tRec.usedRows.map((row) => ({
        row,
        gamma: tagZp(tRec.coefficients.get(row) as bigint),
      })),
      recovered: tagGT(tResult.ok ? tResult.recovered : tMessage),
      matchesMessage: tResult.ok && gtToHex(tResult.recovered) === gtToHex(tMessage),
    },
    kem: {
      hkdfInfo: 'crypto-lab-attribute-gate/FAME-KEM/AES-256-GCM/v1',
      hkdfSalt: 'crypto-lab-attribute-gate/FAME-KEM/salt/v1',
      aesKey: toHex(rawKey),
      nonce: toHex(sealed.nonce),
      aad: sealed.aad,
      sealed: toHex(sealed.ciphertext),
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Helpers the fixture and the UI share                                       */
/* -------------------------------------------------------------------------- */

/**
 * Every random-oracle point the scheme touches for a given label set and
 * matrix width, named so the fixture records what H was asked for.
 *
 * FAME queries H six times per attribute (l in {1,2,3}, t in {1,2}) and six
 * times per MSP column. Counting them is how the element inspector states the
 * cost of a policy without hand-waving.
 */
export function oracleInputsFor(labels: readonly string[], columns: number): string[] {
  const out: string[] = [];
  for (const y of labels) {
    for (const l of L_INDICES) for (const t of T_INDICES) out.push(`H(${y}, ${l}, ${t}) in G1`);
  }
  for (let j = 1; j <= columns; j++) {
    for (const l of L_INDICES) for (const t of T_INDICES) out.push(`H(col ${j}, ${l}, ${t}) in G1`);
  }
  return out;
}

/** Compact display of a tagged element, for the element inspector. */
export function describeTagged(e: TaggedElement): string {
  const width = e.group === 'G1' ? 48 : e.group === 'G2' ? 96 : e.group === 'GT' ? 576 : 32;
  return `${e.group} \u00b7 ${width} bytes \u00b7 ${e.hex.slice(0, 16)}...`;
}
