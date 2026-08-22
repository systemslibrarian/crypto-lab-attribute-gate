/**
 * Collusion: pool two keys, run the real decryption, watch it fail, and show
 * the exact term that refuses to cancel.
 *
 * This is what attribute-based encryption exists for. Without collusion
 * resistance, ABE would be a filing convention: Bob {Doctor} and Eve
 * {Cardiology} could hand each other their key material and read anything
 * either of their attribute sets, unioned, satisfies. Every ABE paper states
 * the property. Almost nothing shows it, because showing it means actually
 * splicing two keys and running decryption on the result.
 *
 * The splice here is real. `poolKeys` builds a `SecretKey` -- the same type
 * `decrypt` takes -- out of components from two different `keygen` calls, and
 * `decrypt` has no idea. There is no collusion check anywhere in the scheme
 * and none is added here. What stops it is structural: every key carries a
 * fresh (r1, r2), the components are blinded with Br = (b1 r1, b2 r2, r1 + r2),
 * and the numerator's sk0 can only cancel the denominator's blinding for
 * components that came from the same key.
 */
import { GT_ONE, gtDiv, gtEquals, gtToHex, mod, type GTElement } from './bls';
import {
  decrypt,
  predictedResidual,
  type Ciphertext,
  type CiphertextWitness,
  type G1Triple,
  type IssuedKey,
  type KeyWitness,
  type SecretKey,
} from './fame';
import type { Reconstruction } from './msp';

export interface PooledKey {
  readonly key: SecretKey;
  /** Which holder each label's component came from. */
  readonly provenance: ReadonlyMap<string, string>;
  /** The holder whose sk0 and sk' the splice uses. */
  readonly baseHolder: string;
  readonly otherHolder: string;
}

/**
 * Splice two issued keys into one.
 *
 * sk0 and sk' must come from a single key -- they are three components of one
 * randomization and mixing them cannot help. Everything else is taken from
 * `base` where it exists and from `other` where it does not, which is the best
 * a pair of colluders can do with the material they hold.
 */
export function poolKeys(base: IssuedKey, other: IssuedKey): PooledKey {
  const sk = new Map<string, G1Triple>();
  const provenance = new Map<string, string>();

  for (const [label, component] of base.key.sk) {
    sk.set(label, component);
    provenance.set(label, base.holder);
  }
  for (const [label, component] of other.key.sk) {
    if (sk.has(label)) continue;
    sk.set(label, component);
    provenance.set(label, other.holder);
  }

  return {
    key: {
      labels: [...sk.keys()],
      sk0: base.key.sk0,
      sk: sk,
      skPrime: base.key.skPrime,
    },
    provenance,
    baseHolder: base.holder,
    otherHolder: other.holder,
  };
}

export interface RowProvenance {
  readonly rowIndex: number;
  readonly label: string;
  readonly holder: string;
  /** true when this row's component came from the same key as sk0 and sk'. */
  readonly coherent: boolean;
  /** Br^base_l - Br^holder_l for l = 1, 2, 3. All zero exactly when coherent. */
  readonly brDelta: readonly [bigint, bigint, bigint];
}

export interface CollusionAnalysis {
  readonly satisfiedPolicy: boolean;
  /** null when the pooled attribute set does not even satisfy the policy. */
  readonly reconstruction: Reconstruction;
  /** What decryption produced. */
  readonly recovered: GTElement | null;
  /** What was actually encapsulated. */
  readonly expected: GTElement;
  /** recovered / expected, straight from the two group elements. */
  readonly residualObserved: GTElement | null;
  /** The same quantity predicted from the r and s values, never touching decrypt. */
  readonly residualPredicted: GTElement;
  /** Do the two routes agree? This is the claim the exhibit makes. */
  readonly routesAgree: boolean;
  /** Is the residual the identity? Equivalently: did decryption actually work? */
  readonly residualIsOne: boolean;
  readonly rows: readonly RowProvenance[];
}

/**
 * Run a pooled key against a ciphertext and explain the outcome two ways.
 *
 * Route 1 divides what decryption produced by what was encapsulated.
 * Route 2 computes the leftover blinding directly from the per-key r values and
 *         the encryptor's s values, by a formula that never calls decrypt.
 * They must agree byte for byte. Comparing them is the difference between
 * asserting collusion resistance and demonstrating it.
 */
export function analyseCollusion(
  ct: Ciphertext,
  pooled: PooledKey,
  witnessByHolder: ReadonlyMap<string, KeyWitness>,
  ctWitness: CiphertextWitness,
): CollusionAnalysis {
  const result = decrypt(ct, pooled.key);
  const baseWitness = witnessByHolder.get(pooled.baseHolder) as KeyWitness;
  const rowByIndex = new Map(ct.msp.rows.map((r) => [r.index, r]));

  const holderForRow = (rowIndex: number): string => {
    const label = (rowByIndex.get(rowIndex) as { label: string }).label;
    return pooled.provenance.get(label) ?? pooled.baseHolder;
  };
  const witnessForRow = (rowIndex: number): KeyWitness =>
    witnessByHolder.get(holderForRow(rowIndex)) as KeyWitness;

  const rec = result.reconstruction;
  const rows: RowProvenance[] = rec.usedRows.map((i) => {
    const holder = holderForRow(i);
    const w = witnessByHolder.get(holder) as KeyWitness;
    const brDelta: [bigint, bigint, bigint] = [
      mod(baseWitness.Br[0] - w.Br[0]),
      mod(baseWitness.Br[1] - w.Br[1]),
      mod(baseWitness.Br[2] - w.Br[2]),
    ];
    return {
      rowIndex: i,
      label: (rowByIndex.get(i) as { label: string }).label,
      holder,
      coherent: holder === pooled.baseHolder,
      brDelta,
    };
  });

  // With no satisfying set there are no rows to sum over, so the empty product
  // is 1 -- the same value predictedResidual would return.
  const residualPredicted = rec.satisfied
    ? predictedResidual(ct, rec, baseWitness, witnessForRow, ctWitness)
    : GT_ONE;

  const recovered = result.ok ? result.recovered : null;
  const residualObserved = recovered ? gtDiv(recovered, ctWitness.encapsulated) : null;

  return {
    satisfiedPolicy: rec.satisfied,
    reconstruction: rec,
    recovered,
    expected: ctWitness.encapsulated,
    residualObserved,
    residualPredicted,
    routesAgree: residualObserved !== null && gtEquals(residualObserved, residualPredicted),
    residualIsOne: residualObserved !== null && gtEquals(residualObserved, GT_ONE),
    rows,
  };
}

/** Short display form for a GT element: first and last bytes of the encoding. */
export function gtFingerprint(x: GTElement): string {
  const hex = gtToHex(x);
  return `${hex.slice(0, 12)}...${hex.slice(-12)}`;
}
