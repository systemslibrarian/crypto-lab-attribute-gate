/**
 * Access policies as monotone threshold trees.
 *
 * FAME consumes a monotone span program, not a tree. The tree is the interface
 * a human can reason about; msp.ts turns it into the matrix the scheme
 * actually uses, and that conversion is one of the things this lab exists to
 * show.
 *
 * Gates are k-of-n threshold gates, which is the general form:
 *   AND over n children = n-of-n
 *   OR  over n children = 1-of-n
 * The FAME paper notes this generality directly (Section 2.1, footnote 5):
 * "OR is a 1-out-of-2 gate and AND is a 2-out-of-2 gate", and warns that with
 * general k-of-n gates the matrix entries leave {-1, 0, 1}. They do here.
 */

export type PolicyNode = AttributeNode | ThresholdNode;

export interface AttributeNode {
  readonly kind: 'attribute';
  /** Stable identity for this leaf, unique within a tree. Also the MSP row id. */
  readonly id: string;
  /** The attribute name as a human writes it, e.g. `Doctor`. Not yet indexed. */
  readonly name: string;
}

export interface ThresholdNode {
  readonly kind: 'threshold';
  readonly id: string;
  /** k in "k of n". 1 is OR, n is AND. */
  readonly threshold: number;
  readonly children: readonly PolicyNode[];
}

/** Every failure this lab can report, as a closed set. */
export type FailureCode =
  | 'POLICY_UNSATISFIED'
  | 'ATTR_MISSING'
  | 'THRESHOLD_NOT_MET'
  | 'COLLUSION_BLOCKED'
  | 'MALFORMED_POLICY'
  | 'ATTRIBUTE_REUSED';

export class PolicyError extends Error {
  constructor(
    readonly code: Extract<FailureCode, 'MALFORMED_POLICY' | 'ATTRIBUTE_REUSED'>,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'PolicyError';
  }
}

/* -------------------------------------------------------------------------- */
/* Construction helpers                                                       */
/* -------------------------------------------------------------------------- */

let autoId = 0;

/** Fresh node id. Ids only need to be unique inside one tree. */
export function nextId(prefix: string): string {
  autoId += 1;
  return `${prefix}${autoId}`;
}

/** Reset the id counter. Test-only, so ids in pinned fixtures stay stable. */
export function resetIds(): void {
  autoId = 0;
}

export function attr(name: string, id = nextId('n')): AttributeNode {
  return { kind: 'attribute', id, name };
}

export function threshold(k: number, children: PolicyNode[], id = nextId('n')): ThresholdNode {
  return { kind: 'threshold', id, threshold: k, children };
}

export function and(children: PolicyNode[], id?: string): ThresholdNode {
  return threshold(children.length, children, id);
}

export function or(children: PolicyNode[], id?: string): ThresholdNode {
  return threshold(1, children, id);
}

/* -------------------------------------------------------------------------- */
/* Validation -- MALFORMED_POLICY                                             */
/* -------------------------------------------------------------------------- */

/** Upper bounds. Not security limits; they stop the UI building a matrix nobody can read. */
export const MAX_LEAVES = 24;
export const MAX_DEPTH = 8;
export const MAX_NAME_LENGTH = 48;

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.\-+/]*$/;

/**
 * Reject anything the scheme cannot consume, fail-closed and named.
 *
 * The colon is reserved: the one-use transform appends `:1`, `:2`, ... to
 * attribute names, so a name that already contains one would make the indexed
 * label ambiguous.
 */
export function validatePolicy(root: PolicyNode): void {
  const ids = new Set<string>();
  let leaves = 0;

  const walk = (node: PolicyNode, depth: number): void => {
    if (depth > MAX_DEPTH) {
      throw new PolicyError('MALFORMED_POLICY', `policy nests deeper than ${MAX_DEPTH} gates`);
    }
    if (ids.has(node.id)) {
      throw new PolicyError('MALFORMED_POLICY', `duplicate node id "${node.id}"`);
    }
    ids.add(node.id);

    if (node.kind === 'attribute') {
      leaves += 1;
      if (leaves > MAX_LEAVES) {
        throw new PolicyError('MALFORMED_POLICY', `policy has more than ${MAX_LEAVES} leaves`);
      }
      if (node.name.length === 0 || node.name.length > MAX_NAME_LENGTH) {
        throw new PolicyError(
          'MALFORMED_POLICY',
          `attribute name must be 1-${MAX_NAME_LENGTH} characters`,
        );
      }
      if (node.name.includes(':')) {
        throw new PolicyError(
          'MALFORMED_POLICY',
          `attribute name "${node.name}" contains ":", which the one-use transform reserves`,
        );
      }
      if (!NAME_RE.test(node.name)) {
        throw new PolicyError(
          'MALFORMED_POLICY',
          `attribute name "${node.name}" has characters outside [A-Za-z0-9 _.-+/]`,
        );
      }
      return;
    }

    const n = node.children.length;
    if (n === 0) {
      throw new PolicyError('MALFORMED_POLICY', 'threshold gate has no children');
    }
    if (!Number.isInteger(node.threshold) || node.threshold < 1 || node.threshold > n) {
      throw new PolicyError(
        'MALFORMED_POLICY',
        `gate needs 1 <= k <= n; got k=${node.threshold}, n=${n}`,
      );
    }
    for (const c of node.children) walk(c, depth + 1);
  };

  walk(root, 1);
  if (leaves === 0) {
    throw new PolicyError('MALFORMED_POLICY', 'policy has no attributes');
  }
}

/* -------------------------------------------------------------------------- */
/* Traversal                                                                  */
/* -------------------------------------------------------------------------- */

/** Leaves in left-to-right order. This order fixes the MSP row order. */
export function leavesOf(root: PolicyNode): AttributeNode[] {
  const out: AttributeNode[] = [];
  const walk = (n: PolicyNode): void => {
    if (n.kind === 'attribute') out.push(n);
    else n.children.forEach(walk);
  };
  walk(root);
  return out;
}

/** How many rows each attribute name would claim. Drives the one-use transform. */
export function attributeMultiplicity(root: PolicyNode): Map<string, number> {
  const counts = new Map<string, number>();
  for (const leaf of leavesOf(root)) {
    counts.set(leaf.name, (counts.get(leaf.name) ?? 0) + 1);
  }
  return counts;
}

/** Human-readable form, used in the UI and in the pinned vectors. */
export function formatPolicy(node: PolicyNode): string {
  if (node.kind === 'attribute') return node.name;
  const parts = node.children.map(formatPolicy);
  const n = node.children.length;
  if (node.threshold === n && n > 1) return `(${parts.join(' AND ')})`;
  if (node.threshold === 1 && n > 1) return `(${parts.join(' OR ')})`;
  if (n === 1) return parts[0];
  return `${node.threshold}-of-${n}(${parts.join(', ')})`;
}

/** Gate label for the UI: "AND", "OR", or "2 of 3". */
export function gateLabel(node: ThresholdNode): string {
  const n = node.children.length;
  if (n > 1 && node.threshold === n) return 'AND';
  if (n > 1 && node.threshold === 1) return 'OR';
  return `${node.threshold} of ${n}`;
}
