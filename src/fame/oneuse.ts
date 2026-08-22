/**
 * FAME's one-use restriction, and the indexed-copy transform that works around it.
 *
 * The paper (Section 3, "One-use restriction"):
 *
 *   "our scheme requires the mapping pi in an MSP to be an injective function,
 *    i.e., no two rows should be mapped to the same attribute. [...] A common
 *    way of getting around this problem [...] is to have k copies of each
 *    attribute in the universe for some fixed k chosen at set-up. For example,
 *    'Title:Prof' will be replaced by 'Title:Prof:1', 'Title:Prof:2', ...,
 *    'Title:Prof:k'. The downside of this transformation is that the size of
 *    keys grows by a factor of k; but note that the encryption and decryption
 *    time is not affected."
 *
 * Appendix C makes clear why it is load-bearing rather than cosmetic: the
 * security reduction rewrites one ciphertext row's mask at a time and needs
 * that row to be "the only place where mu_pi(i) appears" (footnote 15).
 *
 * Two consequences this lab makes visible, because most ABE explainers state
 * the restriction and stop:
 *
 *  1. A realistic policy violates it immediately.
 *     `(Doctor AND Cardiology) OR (Doctor AND Emergency)` uses Doctor twice.
 *
 *  2. The transform is NOT policy-side only. If Doctor becomes Doctor:1 and
 *     Doctor:2, then every key entitled to Doctor must carry BOTH, because the
 *     issuer cannot know which row index a future policy will use. That is the
 *     factor-of-k key growth, and a policy-side-only implementation simply
 *     fails at issuance.
 *
 * The indexed labels are genuinely distinct attributes: they hash to different
 * G1 points. Stripping the index before hashing -- which the authors' Charm
 * reference does, under a comment noting re-use is not allowed -- would make
 * Doctor:1 and Doctor:2 the same attribute again and give back the collision
 * the restriction exists to prevent.
 */
import { PolicyError, attributeMultiplicity, leavesOf, type PolicyNode } from './policy';

/** `Doctor` + copy 2 -> `Doctor:2`. Indices are 1-based, as in the paper. */
export function indexedLabel(name: string, copy: number): string {
  return `${name}:${copy}`;
}

/** Inverse of {@link indexedLabel}. Used for display, never before hashing. */
export function baseName(label: string): string {
  const i = label.lastIndexOf(':');
  return i === -1 ? label : label.slice(0, i);
}

export interface CopyRecord {
  readonly name: string;
  /** How many rows of THIS policy the name claims. */
  readonly copiesUsedHere: number;
  /** The indexed labels this policy's rows carry, in row order. */
  readonly labels: readonly string[];
}

export interface OneUseTransform {
  /** leaf id -> indexed row label. This is pi, and it is injective by construction. */
  readonly rowLabel: ReadonlyMap<string, string>;
  /** Per attribute name, what the transform did. Ordered by first appearance. */
  readonly records: readonly CopyRecord[];
  /** Names that needed more than one copy -- the ones worth showing. */
  readonly reusedNames: readonly string[];
}

/**
 * Rewrite each leaf's row label so pi is injective.
 *
 * The n-th left-to-right occurrence of `Doctor` becomes `Doctor:n`. Every leaf
 * is indexed, including single-use ones: the paper's transform replaces the
 * attribute in the universe, so `Doctor` as such no longer exists.
 */
export function applyOneUseTransform(root: PolicyNode): OneUseTransform {
  const seen = new Map<string, number>();
  const rowLabel = new Map<string, string>();
  const perName = new Map<string, string[]>();

  for (const leaf of leavesOf(root)) {
    const n = (seen.get(leaf.name) ?? 0) + 1;
    seen.set(leaf.name, n);
    const label = indexedLabel(leaf.name, n);
    rowLabel.set(leaf.id, label);
    const list = perName.get(leaf.name);
    if (list) list.push(label);
    else perName.set(leaf.name, [label]);
  }

  const records: CopyRecord[] = [];
  for (const [name, labels] of perName) {
    records.push({ name, copiesUsedHere: labels.length, labels });
  }

  return {
    rowLabel,
    records,
    reusedNames: records.filter((r) => r.copiesUsedHere > 1).map((r) => r.name),
  };
}

/**
 * Assert pi is injective.
 *
 * This is the ATTRIBUTE_REUSED invariant, and per the brief it is an internal
 * one: with the transform in place a duplicate label can never reach the
 * scheme, so if one does, the transform is broken. It is never a user-facing
 * policy verdict -- a user who writes Doctor twice gets a transformed policy,
 * not an error.
 */
export function assertInjective(labels: readonly string[]): void {
  const seen = new Set<string>();
  for (const l of labels) {
    if (seen.has(l)) {
      throw new PolicyError(
        'ATTRIBUTE_REUSED',
        `row label "${l}" appears twice; the one-use transform did not run or is broken`,
      );
    }
    seen.add(l);
  }
}

/* -------------------------------------------------------------------------- */
/* The registry -- how many copies of each attribute a key must carry         */
/* -------------------------------------------------------------------------- */

export interface RegistryGrowth {
  readonly name: string;
  readonly from: number;
  readonly to: number;
}

/**
 * The authority's record of how many indexed copies each attribute needs.
 *
 * The paper fixes k at set-up. Because FAME is large-universe -- attributes are
 * hashed, not enrolled -- nothing in the public key stops k from rising later;
 * what breaks is the keys already issued. So the registry is honest about the
 * cost the paper describes: raising k does not touch pk, it invalidates every
 * key minted under the old k.
 */
export class AttributeRegistry {
  private readonly counts = new Map<string, number>();

  /** Current k for an attribute. Unknown attributes need one copy. */
  copies(name: string): number {
    return this.counts.get(name) ?? 1;
  }

  names(): string[] {
    return [...this.counts.keys()].sort();
  }

  snapshot(): Map<string, number> {
    return new Map(this.counts);
  }

  /** Raise k where a policy demands it. Returns only the attributes that grew. */
  observePolicy(root: PolicyNode): RegistryGrowth[] {
    const growth: RegistryGrowth[] = [];
    for (const [name, used] of attributeMultiplicity(root)) {
      const before = this.copies(name);
      if (used > before) {
        this.counts.set(name, used);
        growth.push({ name, from: before, to: used });
      } else if (!this.counts.has(name)) {
        this.counts.set(name, before);
      }
    }
    return growth;
  }

  /**
   * The indexed labels a key for `held` must carry.
   *
   * This is the second half of the transform. A user entitled to Doctor gets
   * Doctor:1 ... Doctor:k, because issuance cannot know which row index a
   * future policy will use.
   */
  expand(held: readonly string[]): string[] {
    const out: string[] = [];
    for (const name of held) {
      const k = this.copies(name);
      for (let i = 1; i <= k; i++) out.push(indexedLabel(name, i));
    }
    return out;
  }
}
