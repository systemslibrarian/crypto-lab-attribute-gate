/**
 * Monotone threshold trees compiled to the RW15 LSSS `(A, delta)`.
 *
 * Unlike FAME, RW15 explicitly permits repeated attributes. A single key for
 * `Doctor@Hospital` may therefore serve every row carrying that exact logical
 * attribute; occurrence suffixes are never added or hashed.
 */
import { addMod, divMod, mod, mulMod } from '../fame/bls';
import { parseQualifiedAttribute } from './encoding';

export type RwPolicyNode = RwAttributeNode | RwThresholdNode;

export interface RwAttributeNode {
  readonly kind: 'attribute';
  readonly id: string;
  readonly attribute: string;
}

export interface RwThresholdNode {
  readonly kind: 'threshold';
  readonly id: string;
  readonly threshold: number;
  readonly children: readonly RwPolicyNode[];
}

export interface RwLsssRow {
  readonly index: number;
  readonly leafId: string;
  /** Fully qualified logical attribute; duplicates are allowed. */
  readonly attribute: string;
  readonly authority: string;
  readonly vector: readonly bigint[];
}

export interface RwLsss {
  readonly policy: RwPolicyNode;
  readonly rows: readonly RwLsssRow[];
  readonly columns: number;
}

export interface RwReconstruction {
  readonly satisfied: boolean;
  readonly usedRows: readonly number[];
  readonly coefficients: ReadonlyMap<number, bigint>;
  readonly status: ReadonlyMap<string, boolean>;
}

export const RW15_MAX_ROWS = 24;
export const RW15_MAX_DEPTH = 8;

let nextPolicyId = 0;

export function resetRwPolicyIds(): void {
  nextPolicyId = 0;
}

function freshId(prefix: string): string {
  nextPolicyId += 1;
  return `${prefix}${nextPolicyId}`;
}

export function rwAttr(attribute: string, id = freshId('rw-a')): RwAttributeNode {
  return { kind: 'attribute', id, attribute: parseQualifiedAttribute(attribute).qualified };
}

export function rwThreshold(
  threshold: number,
  children: readonly RwPolicyNode[],
  id = freshId('rw-g'),
): RwThresholdNode {
  return { kind: 'threshold', id, threshold, children: [...children] };
}

export function rwAnd(children: readonly RwPolicyNode[], id?: string): RwThresholdNode {
  return rwThreshold(children.length, children, id);
}

export function rwOr(children: readonly RwPolicyNode[], id?: string): RwThresholdNode {
  return rwThreshold(1, children, id);
}

function validatePolicy(root: RwPolicyNode): void {
  const ids = new Set<string>();
  let rows = 0;
  const visit = (node: RwPolicyNode, depth: number): void => {
    if (depth > RW15_MAX_DEPTH) {
      throw new Error(`RW15_POLICY: depth exceeds ${RW15_MAX_DEPTH}`);
    }
    if (ids.has(node.id)) throw new Error(`RW15_POLICY: duplicate node id "${node.id}"`);
    ids.add(node.id);
    if (node.kind === 'attribute') {
      parseQualifiedAttribute(node.attribute);
      rows += 1;
      if (rows > RW15_MAX_ROWS) {
        throw new Error(`RW15_POLICY: more than ${RW15_MAX_ROWS} rows`);
      }
      return;
    }
    if (
      node.children.length === 0 ||
      !Number.isInteger(node.threshold) ||
      node.threshold < 1 ||
      node.threshold > node.children.length
    ) {
      throw new Error(
        `RW15_POLICY: threshold must satisfy 1 <= k <= n; got ${node.threshold}-of-${node.children.length}`,
      );
    }
    node.children.forEach((child) => visit(child, depth + 1));
  };
  visit(root, 1);
}

export function compileRwPolicy(root: RwPolicyNode): RwLsss {
  validatePolicy(root);
  let width = 1;
  const leafVectors = new Map<string, bigint[]>();
  const pad = (input: readonly bigint[], length: number): bigint[] => {
    const out = [...input];
    while (out.length < length) out.push(0n);
    return out;
  };

  const stack: Array<{ node: RwPolicyNode; vector: bigint[] }> = [
    { node: root, vector: [1n] },
  ];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;
    if (current.node.kind === 'attribute') {
      leafVectors.set(current.node.id, current.vector);
      continue;
    }
    const gate = current.node;
    const base = pad(current.vector, width);
    const freshColumns = gate.threshold - 1;
    const children = gate.children.map((child, childIndex) => {
      const vector = [...base];
      let power = 1n;
      const x = BigInt(childIndex + 1);
      for (let column = 0; column < freshColumns; column += 1) {
        power = mulMod(power, x);
        vector.push(power);
      }
      return { node: child, vector };
    });
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
    width += freshColumns;
  }

  const leaves: RwAttributeNode[] = [];
  const collectLeaves = (node: RwPolicyNode): void => {
    if (node.kind === 'attribute') leaves.push(node);
    else node.children.forEach(collectLeaves);
  };
  collectLeaves(root);

  const rows = leaves.map((leaf, index): RwLsssRow => {
    const parsed = parseQualifiedAttribute(leaf.attribute);
    const vector = leafVectors.get(leaf.id);
    if (!vector) throw new Error(`RW15_POLICY: no vector for leaf ${leaf.id}`);
    return {
      index: index + 1,
      leafId: leaf.id,
      attribute: parsed.qualified,
      authority: parsed.authority,
      vector: pad(vector, width),
    };
  });
  return { policy: root, rows, columns: width };
}

function lagrangeAtZero(points: readonly number[]): bigint[] {
  return points.map((point, index) => {
    const xi = BigInt(point);
    let coefficient = 1n;
    points.forEach((other, otherIndex) => {
      if (index === otherIndex) return;
      const xj = BigInt(other);
      coefficient = mulMod(coefficient, divMod(mod(-xj), mod(xi - xj)));
    });
    return coefficient;
  });
}

export function reconstructRw(
  lsss: RwLsss,
  heldAttributes: ReadonlySet<string>,
): RwReconstruction {
  const held = new Set([...heldAttributes].map((attribute) => parseQualifiedAttribute(attribute).qualified));
  const rowsByLeaf = new Map(lsss.rows.map((row) => [row.leafId, row]));
  const status = new Map<string, boolean>();

  const evaluate = (node: RwPolicyNode): boolean => {
    if (node.kind === 'attribute') {
      const ok = held.has(node.attribute);
      status.set(node.id, ok);
      return ok;
    }
    const have = node.children.map(evaluate).filter(Boolean).length;
    const ok = have >= node.threshold;
    status.set(node.id, ok);
    return ok;
  };

  if (!evaluate(lsss.policy)) {
    return { satisfied: false, usedRows: [], coefficients: new Map(), status };
  }

  const coefficients = new Map<number, bigint>();
  const collect = (node: RwPolicyNode, inherited: bigint): void => {
    if (node.kind === 'attribute') {
      const row = rowsByLeaf.get(node.id);
      if (!row) throw new Error(`RW15_POLICY: missing row for ${node.id}`);
      coefficients.set(row.index, addMod(coefficients.get(row.index) ?? 0n, inherited));
      return;
    }
    const chosen = node.children
      .map((child, index) => ({ child, point: index + 1 }))
      .filter(({ child }) => status.get(child.id))
      .slice(0, node.threshold);
    const basis = lagrangeAtZero(chosen.map(({ point }) => point));
    chosen.forEach(({ child }, index) => collect(child, mulMod(inherited, basis[index])));
  };
  collect(lsss.policy, 1n);
  const usedRows = [...coefficients.keys()].sort((a, b) => a - b);
  return { satisfied: true, usedRows, coefficients, status };
}

export function formatRwPolicy(node: RwPolicyNode): string {
  if (node.kind === 'attribute') return node.attribute;
  const children = node.children.map(formatRwPolicy);
  if (node.children.length > 1 && node.threshold === node.children.length) {
    return `(${children.join(' AND ')})`;
  }
  if (node.children.length > 1 && node.threshold === 1) {
    return `(${children.join(' OR ')})`;
  }
  if (node.children.length === 1) return children[0];
  return `${node.threshold}-of-${node.children.length}(${children.join(', ')})`;
}
