/**
 * Access tree -> monotone span program (LSSS matrix), and back again.
 *
 * This is the step most ABE explanations skip, and it is where the intuition
 * lives: FAME never sees a tree. It sees a matrix M with n1 rows and n2
 * columns, plus a row-labelling map pi. A key satisfies the ciphertext exactly
 * when the rows it owns can be combined to reach (1, 0, ..., 0):
 *
 *     sum_{i in I} gamma_i * M_i = (1, 0, ..., 0)          (paper, eq. 2.1)
 *
 * Construction used here: Shamir sharing at every gate, applied top-down.
 * A gate holding share lambda = <v, rho> splits it with a degree-(k-1)
 * polynomial q(x) = lambda + u_1 x + ... + u_{k-1} x^(k-1). Child i gets q(i),
 * which in matrix terms is the row `v` followed by (i, i^2, ..., i^(k-1)) in
 * k-1 freshly allocated columns. Reconstruction is Lagrange interpolation at 0
 * over the child indices, multiplied down the path from the root.
 *
 * Why not Lewko-Waters. LW's conversion for AND/OR formulas keeps every entry
 * in {-1, 0, 1} and always admits 0/1 reconstruction coefficients, which FAME
 * likes because it removes every exponentiation from decryption. It has no
 * general k-of-n gate. The paper's own footnote 5 grants the trade: "If a
 * formula has general k-out-of-n threshold gates, then M's entries may have a
 * larger range." This lab takes the general construction, pays the
 * exponentiations, and gets a visible Lagrange step in return. Both are valid
 * MSPs for the same access structure; msp.test.ts checks eq. 2.1 directly
 * rather than trusting either.
 */
import { addMod, divMod, mod, mulMod, ORDER } from './bls';
import {
  leavesOf,
  validatePolicy,
  type AttributeNode,
  type PolicyNode,
  type ThresholdNode,
} from './policy';
import { applyOneUseTransform, assertInjective, type OneUseTransform } from './oneuse';

export interface MspRow {
  /** Row index, 1-based, matching the paper's i. */
  readonly index: number;
  /** Leaf this row came from. */
  readonly leafId: string;
  /** The attribute a human wrote. */
  readonly name: string;
  /** pi(i): the indexed label the scheme hashes. Injective across rows. */
  readonly label: string;
  /** The row of M, length = columns. */
  readonly vector: readonly bigint[];
}

export interface Msp {
  readonly rows: readonly MspRow[];
  readonly columns: number;
  /** Which gate allocated each column, for the UI. Column 1 is the secret itself. */
  readonly columnOwner: readonly (string | null)[];
  readonly transform: OneUseTransform;
}

/**
 * Convert a validated policy tree into (M, pi).
 *
 * @throws PolicyError MALFORMED_POLICY via validatePolicy, or ATTRIBUTE_REUSED
 *         if the one-use transform failed to make pi injective.
 */
export function policyToMsp(root: PolicyNode): Msp {
  validatePolicy(root);
  const transform = applyOneUseTransform(root);

  interface Pending {
    node: PolicyNode;
    vector: bigint[];
  }

  let width = 1;
  const columnOwner: (string | null)[] = [null];
  const leafVectors = new Map<string, bigint[]>();

  const pad = (v: bigint[], to: number): bigint[] => {
    const out = v.slice();
    while (out.length < to) out.push(0n);
    return out;
  };

  const stack: Pending[] = [{ node: root, vector: [1n] }];
  while (stack.length > 0) {
    const { node, vector } = stack.pop() as Pending;
    if (node.kind === 'attribute') {
      leafVectors.set(node.id, vector);
      continue;
    }
    const gate = node as ThresholdNode;
    const k = gate.threshold;
    const base = pad(vector, width);

    if (k === 1) {
      // 1-of-n: q is the constant lambda, so every child gets the same share
      // and no new column is needed.
      for (const child of gate.children) {
        stack.push({ node: child, vector: base.slice() });
      }
      continue;
    }

    const newColumns = k - 1;
    for (let c = 0; c < newColumns; c++) columnOwner.push(gate.id);

    gate.children.forEach((child, idx) => {
      const x = BigInt(idx + 1);
      const row = base.slice();
      let power = 1n;
      for (let c = 0; c < newColumns; c++) {
        power = mulMod(power, x); // x^1, x^2, ..., x^(k-1)
        row.push(power);
      }
      stack.push({ node: child, vector: row });
    });
    width += newColumns;
  }

  const rows: MspRow[] = leavesOf(root).map((leaf, i) => {
    const label = transform.rowLabel.get(leaf.id);
    const vector = leafVectors.get(leaf.id);
    /* c8 ignore next 3 -- both maps are populated from the same leaf walk */
    if (label === undefined || vector === undefined) {
      throw new Error(`internal: leaf ${leaf.id} was not assigned a row`);
    }
    return { index: i + 1, leafId: leaf.id, name: leaf.name, label, vector: pad(vector, width) };
  });

  assertInjective(rows.map((r) => r.label));

  return { rows, columns: width, columnOwner, transform };
}

/* -------------------------------------------------------------------------- */
/* Satisfaction and reconstruction                                            */
/* -------------------------------------------------------------------------- */

export type NodeStatus =
  | { readonly satisfied: true }
  | { readonly satisfied: false; readonly reason: 'ATTR_MISSING'; readonly missing: string }
  | {
      readonly satisfied: false;
      readonly reason: 'THRESHOLD_NOT_MET';
      readonly have: number;
      readonly need: number;
    };

export interface Reconstruction {
  readonly satisfied: boolean;
  /** Per-node verdict, for highlighting the tree. */
  readonly status: ReadonlyMap<string, NodeStatus>;
  /** gamma_i by row index, for the rows actually used. Empty when unsatisfied. */
  readonly coefficients: ReadonlyMap<number, bigint>;
  /** Row indices used, in row order. */
  readonly usedRows: readonly number[];
  /** Every Lagrange step taken, so the UI can show the interpolation. */
  readonly lagrangeSteps: readonly LagrangeStep[];
}

export interface LagrangeStep {
  readonly gateId: string;
  readonly gateLabel: string;
  /** Child positions (1-based) chosen at this gate. */
  readonly points: readonly number[];
  /** lambda_x for each chosen point, in the same order. */
  readonly basis: readonly bigint[];
  /** The coefficient inherited from above, before this gate's basis is applied. */
  readonly inherited: bigint;
}

/**
 * Lagrange basis coefficients at x = 0 over the given points.
 *
 *   lambda_i = prod_{j != i} (0 - x_j) / (x_i - x_j)
 *
 * Hand-rolled with the modular inverse from bls.ts: this is the arithmetic the
 * threshold exhibit shows on screen, so it should not be hidden in a library.
 */
export function lagrangeAtZero(points: readonly number[]): bigint[] {
  const xs = points.map((p) => BigInt(p));
  return xs.map((xi, i) => {
    let acc = 1n;
    xs.forEach((xj, j) => {
      if (i === j) return;
      acc = mulMod(acc, divMod(mod(-xj), mod(xi - xj)));
    });
    return acc;
  });
}

/**
 * Decide whether `heldLabels` satisfies the policy, and if so produce the
 * reconstruction coefficients.
 *
 * `heldLabels` are indexed labels (`Doctor:1`), because that is what a key
 * actually carries after the one-use transform.
 */
export function reconstruct(
  root: PolicyNode,
  msp: Msp,
  heldLabels: ReadonlySet<string>,
): Reconstruction {
  const status = new Map<string, NodeStatus>();
  const rowByLeaf = new Map(msp.rows.map((r) => [r.leafId, r]));

  const evaluate = (node: PolicyNode): boolean => {
    if (node.kind === 'attribute') {
      const row = rowByLeaf.get(node.id);
      /* c8 ignore next -- every leaf has a row by construction */
      const label = row ? row.label : node.name;
      const ok = heldLabels.has(label);
      status.set(node.id, ok ? { satisfied: true } : { satisfied: false, reason: 'ATTR_MISSING', missing: label });
      return ok;
    }
    const results = node.children.map(evaluate);
    const have = results.filter(Boolean).length;
    const ok = have >= node.threshold;
    status.set(
      node.id,
      ok
        ? { satisfied: true }
        : { satisfied: false, reason: 'THRESHOLD_NOT_MET', have, need: node.threshold },
    );
    return ok;
  };

  const satisfied = evaluate(root);
  if (!satisfied) {
    return {
      satisfied: false,
      status,
      coefficients: new Map(),
      usedRows: [],
      lagrangeSteps: [],
    };
  }

  const coefficients = new Map<number, bigint>();
  const lagrangeSteps: LagrangeStep[] = [];

  const collect = (node: PolicyNode, multiplier: bigint): void => {
    if (node.kind === 'attribute') {
      const row = rowByLeaf.get(node.id) as MspRow;
      coefficients.set(row.index, addMod(coefficients.get(row.index) ?? 0n, multiplier));
      return;
    }
    // Take the first k satisfied children. Any k would reconstruct; taking the
    // leftmost keeps the exhibit deterministic and matches reading order.
    const chosen: { position: number; child: PolicyNode }[] = [];
    node.children.forEach((child, idx) => {
      if (chosen.length < node.threshold && status.get(child.id)?.satisfied) {
        chosen.push({ position: idx + 1, child });
      }
    });
    const points = chosen.map((c) => c.position);
    const basis = lagrangeAtZero(points);
    lagrangeSteps.push({
      gateId: node.id,
      gateLabel: `${node.threshold} of ${node.children.length}`,
      points,
      basis,
      inherited: multiplier,
    });
    chosen.forEach((c, i) => collect(c.child, mulMod(multiplier, basis[i])));
  };

  collect(root, 1n);

  const usedRows = [...coefficients.entries()]
    .filter(([, g]) => g !== 0n)
    .map(([i]) => i)
    .sort((a, b) => a - b);

  return { satisfied: true, status, coefficients, usedRows, lagrangeSteps };
}

/**
 * Check eq. 2.1 directly: sum gamma_i * M_i == (1, 0, ..., 0).
 *
 * Used by the tests and printed by the threshold exhibit. Recomputing the
 * combination is the only honest way to claim the reconstruction is right --
 * asserting that decryption worked would just be asserting the same code twice.
 */
export function combineRows(msp: Msp, coefficients: ReadonlyMap<number, bigint>): bigint[] {
  const out = new Array<bigint>(msp.columns).fill(0n);
  for (const row of msp.rows) {
    const g = coefficients.get(row.index);
    if (g === undefined || g === 0n) continue;
    for (let c = 0; c < msp.columns; c++) {
      out[c] = addMod(out[c], mulMod(g, row.vector[c]));
    }
  }
  return out;
}

export function isTargetVector(v: readonly bigint[]): boolean {
  if (v.length === 0) return false;
  if (mod(v[0]) !== 1n) return false;
  return v.slice(1).every((x) => mod(x) === 0n);
}

/**
 * Render a matrix entry the way the exhibit shows it: small negatives as `-1`
 * rather than as p-1, which is the same field element and unreadable.
 */
export function formatEntry(x: bigint, window = 64n): string {
  const v = mod(x);
  if (v > ORDER - window) return `-${(ORDER - v).toString()}`;
  if (v < window) return v.toString();
  return `${v.toString(16).slice(0, 6)}...`;
}

/** Leaves in row order, for panels that iterate the tree and the matrix together. */
export function rowsWithLeaves(root: PolicyNode, msp: Msp): { row: MspRow; leaf: AttributeNode }[] {
  const leaves = new Map(leavesOf(root).map((l) => [l.id, l]));
  return msp.rows.map((row) => ({ row, leaf: leaves.get(row.leafId) as AttributeNode }));
}

/**
 * A minimal set of row labels that satisfies the policy, ignoring any key.
 *
 * Used by the escrow exhibit: the authority does not hold a key, it holds msk,
 * so the first of its two steps is choosing which attributes to mint itself.
 * Returns null only for a tree no attribute set could satisfy, which
 * validatePolicy already rules out.
 */
export function minimalSatisfyingLabels(root: PolicyNode, msp: Msp): string[] {
  const labelByLeaf = new Map(msp.rows.map((r) => [r.leafId, r.label]));
  const out: string[] = [];
  const walk = (node: PolicyNode): void => {
    if (node.kind === 'attribute') {
      out.push(labelByLeaf.get(node.id) as string);
      return;
    }
    node.children.slice(0, node.threshold).forEach(walk);
  };
  walk(root);
  return out;
}
