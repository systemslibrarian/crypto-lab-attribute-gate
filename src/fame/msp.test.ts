import { describe, expect, it } from 'vitest';
import { mod, ORDER } from './bls';
import {
  attr,
  and,
  or,
  threshold,
  formatPolicy,
  PolicyError,
  resetIds,
  validatePolicy,
  type PolicyNode,
} from './policy';
import {
  combineRows,
  isTargetVector,
  lagrangeAtZero,
  minimalSatisfyingLabels,
  policyToMsp,
  reconstruct,
} from './msp';
import { applyOneUseTransform, AttributeRegistry } from './oneuse';

/** Every subset of a list, for exhaustive satisfaction checks. */
function subsets<T>(xs: readonly T[]): T[][] {
  return xs.reduce<T[][]>((acc, x) => acc.concat(acc.map((s) => [...s, x])), [[]]);
}

/** Reference evaluator: recompute satisfaction from the tree, not from the MSP. */
function treeSatisfied(node: PolicyNode, labels: ReadonlySet<string>, pi: ReadonlyMap<string, string>): boolean {
  if (node.kind === 'attribute') return labels.has(pi.get(node.id) as string);
  const ok = node.children.filter((c) => treeSatisfied(c, labels, pi)).length;
  return ok >= node.threshold;
}

describe('policy validation (MALFORMED_POLICY)', () => {
  it('accepts a well-formed tree', () => {
    expect(() => validatePolicy(or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]))).not.toThrow();
  });

  it('rejects k greater than n', () => {
    expect(() => validatePolicy(threshold(3, [attr('A'), attr('B')]))).toThrowError(/MALFORMED_POLICY/);
  });

  it('rejects k below 1', () => {
    expect(() => validatePolicy(threshold(0, [attr('A')]))).toThrowError(/MALFORMED_POLICY/);
  });

  it('rejects a gate with no children', () => {
    expect(() => validatePolicy(threshold(1, []))).toThrowError(/MALFORMED_POLICY/);
  });

  it('rejects an empty attribute name', () => {
    expect(() => validatePolicy(attr(''))).toThrowError(/MALFORMED_POLICY/);
  });

  it('reserves the colon for the one-use transform', () => {
    expect(() => validatePolicy(attr('Doctor:1'))).toThrowError(/reserves/);
  });

  it('rejects a name with characters outside the allowed set', () => {
    expect(() => validatePolicy(attr('Doc<script>'))).toThrowError(/MALFORMED_POLICY/);
  });

  it('rejects duplicate node ids', () => {
    expect(() => validatePolicy(and([attr('A', 'dup'), attr('B', 'dup')]))).toThrowError(/duplicate node id/);
  });

  it('rejects a tree deeper than the limit', () => {
    let node: PolicyNode = attr('Leaf');
    for (let i = 0; i < 9; i++) node = and([node, attr(`Pad${i}`)]);
    expect(() => validatePolicy(node)).toThrowError(/nests deeper/);
  });

  it('carries the code on the error object', () => {
    try {
      validatePolicy(threshold(9, [attr('A')]));
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(PolicyError);
      expect((e as PolicyError).code).toBe('MALFORMED_POLICY');
    }
  });
});

describe('the one-use transform', () => {
  it('indexes every leaf, including single-use ones', () => {
    const p = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    const t = applyOneUseTransform(p);
    expect([...t.rowLabel.values()]).toEqual(['Doctor:1', 'Cardiology:1', 'Emergency:1']);
    expect(t.reusedNames).toEqual([]);
  });

  it('gives a reused attribute distinct indexed labels', () => {
    const p = or([and([attr('Doctor'), attr('Cardiology')]), and([attr('Doctor'), attr('Emergency')])]);
    const t = applyOneUseTransform(p);
    expect([...t.rowLabel.values()]).toEqual(['Doctor:1', 'Cardiology:1', 'Doctor:2', 'Emergency:1']);
    expect(t.reusedNames).toEqual(['Doctor']);
  });

  it('makes pi injective, which is what FAME requires', () => {
    const p = or([and([attr('Doctor'), attr('X')]), and([attr('Doctor'), attr('Y')]), attr('Doctor')]);
    const msp = policyToMsp(p);
    const labels = msp.rows.map((r) => r.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it('registry grows k and expands issued keys to match', () => {
    const reg = new AttributeRegistry();
    reg.observePolicy(or([attr('Doctor'), attr('Nurse')]));
    expect(reg.expand(['Doctor'])).toEqual(['Doctor:1']);

    const growth = reg.observePolicy(and([attr('Doctor'), or([attr('Doctor'), attr('Emergency')])]));
    expect(growth).toEqual([{ name: 'Doctor', from: 1, to: 2 }]);
    expect(reg.expand(['Doctor'])).toEqual(['Doctor:1', 'Doctor:2']);
    // The factor-of-k key growth the paper names, measured rather than asserted.
    expect(reg.expand(['Doctor']).length).toBe(2 * reg.expand(['Emergency']).length);
  });

  it('never lowers k once raised', () => {
    const reg = new AttributeRegistry();
    reg.observePolicy(and([attr('Doctor'), attr('Doctor')]));
    expect(reg.copies('Doctor')).toBe(2);
    reg.observePolicy(attr('Doctor'));
    expect(reg.copies('Doctor')).toBe(2);
  });
});

describe('tree to MSP matrix', () => {
  it('builds the matrix the worked example uses', () => {
    resetIds();
    const p = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    const msp = policyToMsp(p);
    expect(msp.columns).toBe(2);
    expect(msp.rows.map((r) => [r.label, r.vector.map(Number)])).toEqual([
      ['Doctor:1', [1, 1]],
      ['Cardiology:1', [1, 2]],
      ['Emergency:1', [1, 0]],
    ]);
  });

  it('an OR gate allocates no column', () => {
    const msp = policyToMsp(or([attr('A'), attr('B'), attr('C')]));
    expect(msp.columns).toBe(1);
    expect(msp.rows.every((r) => r.vector.length === 1 && r.vector[0] === 1n)).toBe(true);
  });

  it('a k-of-n gate allocates exactly k-1 columns', () => {
    const msp = policyToMsp(threshold(2, [attr('A'), attr('B'), attr('C')]));
    expect(msp.columns).toBe(2);
    const msp3 = policyToMsp(threshold(3, [attr('A'), attr('B'), attr('C'), attr('D')]));
    expect(msp3.columns).toBe(3);
  });

  it('a threshold row is the Vandermonde evaluation (1, i, i^2, ...)', () => {
    const msp = policyToMsp(threshold(3, [attr('A'), attr('B'), attr('C')]));
    expect(msp.rows.map((r) => r.vector.map(Number))).toEqual([
      [1, 1, 1],
      [1, 2, 4],
      [1, 3, 9],
    ]);
  });

  it('column 1 is the secret column and is owned by no gate', () => {
    const msp = policyToMsp(and([attr('A'), attr('B')]));
    expect(msp.columnOwner[0]).toBeNull();
    expect(msp.columnOwner.slice(1).every((o) => typeof o === 'string')).toBe(true);
    expect(msp.columnOwner.length).toBe(msp.columns);
  });
});

describe('Lagrange reconstruction', () => {
  it('a single point interpolates to 1', () => {
    expect(lagrangeAtZero([1])).toEqual([1n]);
    expect(lagrangeAtZero([7])).toEqual([1n]);
  });

  it('two points give the familiar 2 and -1', () => {
    const [l1, l2] = lagrangeAtZero([1, 2]);
    expect(l1).toBe(2n);
    expect(l2).toBe(mod(-1n));
  });

  it('the basis sums to 1 at zero for any point set', () => {
    for (const pts of [[1], [1, 2], [2, 3], [1, 2, 3], [1, 3, 4], [2, 4, 5, 7]]) {
      const sum = lagrangeAtZero(pts).reduce((a, b) => mod(a + b), 0n);
      expect(sum).toBe(1n);
    }
  });

  it('reproduces a constant polynomial through its own points', () => {
    // q(x) = 5 + 3x + 2x^2, shares at x = 1,2,3 must interpolate back to 5.
    const q = (x: bigint) => mod(5n + 3n * x + 2n * x * x);
    const pts = [1, 2, 3];
    const basis = lagrangeAtZero(pts);
    const back = pts.reduce((acc, x, i) => mod(acc + basis[i] * q(BigInt(x))), 0n);
    expect(back).toBe(5n);
  });
});

describe('eq. 2.1 -- sum gamma_i M_i = (1, 0, ..., 0)', () => {
  const policies: { name: string; policy: () => PolicyNode; universe: string[] }[] = [
    {
      name: '(Doctor AND Cardiology) OR Emergency',
      policy: () => or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]),
      universe: ['Doctor', 'Cardiology', 'Emergency'],
    },
    {
      name: '2-of-3',
      policy: () => threshold(2, [attr('A'), attr('B'), attr('C')]),
      universe: ['A', 'B', 'C'],
    },
    {
      name: '3-of-4 nested under an AND',
      policy: () =>
        and([attr('Staff'), threshold(3, [attr('A'), attr('B'), attr('C'), attr('D')])]),
      universe: ['Staff', 'A', 'B', 'C', 'D'],
    },
    {
      name: 'reused attribute across two branches',
      policy: () =>
        or([and([attr('Doctor'), attr('Cardiology')]), and([attr('Doctor'), attr('Emergency')])]),
      universe: ['Doctor', 'Cardiology', 'Emergency'],
    },
    {
      name: 'deep mix',
      policy: () =>
        threshold(2, [
          and([attr('P'), attr('Q')]),
          or([attr('R'), attr('S')]),
          threshold(2, [attr('T'), attr('U'), attr('V')]),
        ]),
      universe: ['P', 'Q', 'R', 'S', 'T', 'U', 'V'],
    },
  ];

  for (const { name, policy, universe } of policies) {
    it(`holds for every satisfying subset of ${name}`, () => {
      const p = policy();
      const msp = policyToMsp(p);
      const pi = msp.transform.rowLabel;
      // A key holds every indexed copy of a name it owns.
      const labelsFor = (names: readonly string[]): Set<string> => {
        const held = new Set<string>();
        for (const row of msp.rows) if (names.includes(row.name)) held.add(row.label);
        return held;
      };

      let satisfyingSeen = 0;
      let unsatisfyingSeen = 0;
      for (const names of subsets(universe)) {
        const held = labelsFor(names);
        const expected = treeSatisfied(p, held, pi);
        const rec = reconstruct(p, msp, held);
        expect(rec.satisfied, `subset {${names.join(',')}}`).toBe(expected);
        if (!expected) {
          unsatisfyingSeen += 1;
          expect(rec.coefficients.size).toBe(0);
          continue;
        }
        satisfyingSeen += 1;
        const combined = combineRows(msp, rec.coefficients);
        expect(isTargetVector(combined), `subset {${names.join(',')}} -> ${combined}`).toBe(true);
        // Only rows the key actually holds may carry a non-zero coefficient.
        for (const [i, g] of rec.coefficients) {
          if (g === 0n) continue;
          expect(held.has(msp.rows[i - 1].label)).toBe(true);
        }
      }
      expect(satisfyingSeen).toBeGreaterThan(0);
      expect(unsatisfyingSeen).toBeGreaterThan(0);
    });
  }
});

describe('failure diagnosis', () => {
  it('names the missing attribute on a leaf', () => {
    const p = and([attr('Doctor', 'd'), attr('Cardiology', 'c')]);
    const msp = policyToMsp(p);
    const rec = reconstruct(p, msp, new Set(['Doctor:1']));
    expect(rec.satisfied).toBe(false);
    const leaf = rec.status.get('c');
    expect(leaf).toEqual({ satisfied: false, reason: 'ATTR_MISSING', missing: 'Cardiology:1' });
  });

  it('reports THRESHOLD_NOT_MET with the counts', () => {
    const p = threshold(2, [attr('A'), attr('B'), attr('C')], 'gate');
    const msp = policyToMsp(p);
    const rec = reconstruct(p, msp, new Set(['A:1']));
    expect(rec.status.get('gate')).toEqual({
      satisfied: false,
      reason: 'THRESHOLD_NOT_MET',
      have: 1,
      need: 2,
    });
  });

  it('a satisfied gate reports satisfied', () => {
    const p = threshold(2, [attr('A'), attr('B'), attr('C')], 'gate');
    const msp = policyToMsp(p);
    const rec = reconstruct(p, msp, new Set(['A:1', 'C:1']));
    expect(rec.status.get('gate')).toEqual({ satisfied: true });
    // Rows 1 and 3 -- the gate takes the leftmost k satisfied children, and B is absent.
    expect(rec.usedRows).toEqual([1, 3]);
    expect(rec.lagrangeSteps[0].points).toEqual([1, 3]);
  });
});

describe('helpers', () => {
  it('formatPolicy renders AND, OR and thresholds distinctly', () => {
    expect(formatPolicy(or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]))).toBe(
      '((Doctor AND Cardiology) OR Emergency)',
    );
    expect(formatPolicy(threshold(2, [attr('A'), attr('B'), attr('C')]))).toBe('2-of-3(A, B, C)');
  });

  it('minimalSatisfyingLabels picks the leftmost k at every gate', () => {
    const p = threshold(2, [attr('A'), attr('B'), attr('C')]);
    const msp = policyToMsp(p);
    expect(minimalSatisfyingLabels(p, msp)).toEqual(['A:1', 'B:1']);
    const rec = reconstruct(p, msp, new Set(minimalSatisfyingLabels(p, msp)));
    expect(rec.satisfied).toBe(true);
  });

  it('isTargetVector rejects anything that is not e1', () => {
    expect(isTargetVector([1n, 0n, 0n])).toBe(true);
    expect(isTargetVector([1n, 1n])).toBe(false);
    expect(isTargetVector([2n, 0n])).toBe(false);
    expect(isTargetVector([])).toBe(false);
    expect(isTargetVector([mod(ORDER + 1n), 0n])).toBe(true);
  });
});
