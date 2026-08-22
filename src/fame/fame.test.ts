import { describe, expect, it } from 'vitest';
import {
  G1_BYTES,
  G2_BYTES,
  GT_BYTES,
  GT_ONE,
  L_INDICES,
  T_INDICES,
  addMod,
  divMod,
  g1,
  g1Pow,
  g2,
  gtEquals,
  gtMul,
  gtPow,
  gtToHex,
  g1ToHex,
  g2ToHex,
  hashAttribute,
  hashColumn,
  invMod,
  mod,
  mulMod,
  ORDER,
  pairing,
} from './bls';
import { inField, seededRandom } from './rand';
import { and, attr, or, threshold, type PolicyNode } from './policy';
import { minimalSatisfyingLabels, policyToMsp, reconstruct } from './msp';
import {
  decrypt,
  encrypt,
  keygen,
  predictedResidual,
  randomGT,
  setup,
  type IssuedKey,
} from './fame';
import { analyseCollusion, poolKeys } from './collusion';

const rng = seededRandom('crypto-lab-attribute-gate/test');

function issue(
  msk: ReturnType<typeof setup>['msk'],
  holder: string,
  labels: string[],
): IssuedKey {
  const { key, witness } = keygen(msk, labels, rng, holder);
  return { holder, heldNames: labels, key, witness, copiesAtIssue: new Map() };
}

describe('field arithmetic (hand-rolled, because FAME divides by a_t everywhere)', () => {
  it('invMod inverts', () => {
    for (const x of [1n, 2n, 3n, 12345n, ORDER - 1n]) {
      expect(mulMod(x, invMod(x))).toBe(1n);
    }
  });

  it('invMod refuses zero', () => {
    expect(() => invMod(0n)).toThrowError(/no inverse/);
    expect(() => invMod(ORDER)).toThrowError(/no inverse/);
  });

  it('mod normalises negatives into [0, p)', () => {
    expect(mod(-1n)).toBe(ORDER - 1n);
    expect(inField(mod(-ORDER * 3n - 5n))).toBe(true);
  });

  it('divMod is multiplication by the inverse', () => {
    expect(divMod(10n, 5n)).toBe(2n);
    expect(mulMod(divMod(7n, 3n), 3n)).toBe(7n);
  });
});

describe('the pairing is bilinear -- checked, not assumed', () => {
  it('e(g^a, h^b) = e(g,h)^(ab)', () => {
    const a = rng.scalar('bilin-a');
    const b = rng.scalar('bilin-b');
    const lhs = pairing(g1Pow(g1, a), g2.multiply(mod(b)));
    const rhs = gtPow(pairing(g1, g2), mulMod(a, b));
    expect(gtEquals(lhs, rhs)).toBe(true);
  });

  it('the identity in either source group pairs to 1', () => {
    expect(gtEquals(pairing(g1Pow(g1, 0n), g2), GT_ONE)).toBe(true);
  });

  it('encodings are the documented sizes', () => {
    expect(g1ToHex(g1).length).toBe(G1_BYTES * 2);
    expect(g2ToHex(g2).length).toBe(G2_BYTES * 2);
    expect(gtToHex(pairing(g1, g2)).length).toBe(GT_BYTES * 2);
  });
});

describe('H is a random oracle into G1 with visible typing', () => {
  it('different attribute labels give different points', () => {
    const a = hashAttribute('Doctor:1', 1, 1);
    const b = hashAttribute('Doctor:2', 1, 1);
    expect(g1ToHex(a)).not.toBe(g1ToHex(b));
  });

  it('the indexed copies really are distinct attributes', () => {
    // If the index were stripped before hashing -- as the authors' Charm
    // reference does under a "re-use not allowed" comment -- these would be
    // equal, and the one-use restriction would be back.
    const seen = new Set<string>();
    for (let i = 1; i <= 4; i++) seen.add(g1ToHex(hashAttribute(`Doctor:${i}`, 2, 1)));
    expect(seen.size).toBe(4);
  });

  it('l and t index into different points', () => {
    const seen = new Set<string>();
    for (const l of L_INDICES) for (const t of T_INDICES) seen.add(g1ToHex(hashAttribute('X:1', l, t)));
    expect(seen.size).toBe(6);
  });

  it('column hashes are separated from attribute hashes', () => {
    const seen = new Set<string>();
    for (let j = 1; j <= 3; j++) seen.add(g1ToHex(hashColumn(j, 1, 1)));
    seen.add(g1ToHex(hashAttribute('1', 1, 1)));
    expect(seen.size).toBe(4);
  });

  it('the length-prefixed encoding removes the reference implementation ambiguity', () => {
    // Charm concatenates decimal strings: H("Doctor:1" + "1" + "1") and
    // H("Doctor:11" + "1") are the same input there. They must not be here.
    expect(g1ToHex(hashAttribute('Doctor:1', 1, 1))).not.toBe(g1ToHex(hashAttribute('Doctor:11', 1, 1)));
  });

  it('is deterministic', () => {
    expect(g1ToHex(hashAttribute('Doctor:1', 3, 2))).toBe(g1ToHex(hashAttribute('Doctor:1', 3, 2)));
  });
});

describe('Setup produces the public key Figure 3.1 specifies', () => {
  it('T1 and T2 are the paper\'s combinations, recomputed independently', () => {
    const local = seededRandom('setup-shape');
    const { pk, msk } = setup(local);
    // Re-derive from msk by a different route: pair g^d_t with h^a_t and
    // multiply in e(g^d3, h). This never touches the setup code path.
    const [a1, a2] = msk.a;
    const T1 = gtMul(pairing(msk.gd[0], g2.multiply(a1)), pairing(msk.gd[2], g2));
    const T2 = gtMul(pairing(msk.gd[1], g2.multiply(a2)), pairing(msk.gd[2], g2));
    expect(gtEquals(pk.T1, T1)).toBe(true);
    expect(gtEquals(pk.T2, T2)).toBe(true);
  });

  it('H1 = h^a1 and H2 = h^a2', () => {
    const local = seededRandom('setup-h');
    const { pk, msk } = setup(local);
    expect(g2ToHex(pk.H1)).toBe(g2ToHex(g2.multiply(msk.a[0])));
    expect(g2ToHex(pk.H2)).toBe(g2ToHex(g2.multiply(msk.a[1])));
  });

  it('a1, a2, b1, b2 are non-zero -- the scheme divides by a_t', () => {
    const local = seededRandom('setup-nonzero');
    const { msk } = setup(local);
    for (const x of [...msk.a, ...msk.b]) {
      expect(x).not.toBe(0n);
      expect(inField(x)).toBe(true);
    }
  });
});

describe('KeyGen', () => {
  const { msk } = setup(seededRandom('keygen'));

  it('sk0 is (h^b1r1, h^b2r2, h^(r1+r2))', () => {
    const { key, witness } = keygen(msk, ['Doctor:1'], rng, 'shape');
    expect(g2ToHex(key.sk0[0])).toBe(g2ToHex(g2.multiply(witness.Br[0])));
    expect(g2ToHex(key.sk0[1])).toBe(g2ToHex(g2.multiply(witness.Br[1])));
    expect(g2ToHex(key.sk0[2])).toBe(g2ToHex(g2.multiply(witness.Br[2])));
    expect(witness.Br[2]).toBe(addMod(witness.r1, witness.r2));
  });

  it('sk_y,t is the product Figure 3.1 writes, recomputed from the witness', () => {
    const { key, witness } = keygen(msk, ['Doctor:1'], rng, 'component');
    const sigma = witness.sigma.get('Doctor:1') as bigint;
    for (const t of T_INDICES) {
      const at = msk.a[t - 1];
      let acc = g1Pow(g1, divMod(sigma, at));
      for (const l of L_INDICES) {
        acc = acc.add(hashAttribute('Doctor:1', l, t).multiply(mod(divMod(witness.Br[l - 1], at))));
      }
      expect(g1ToHex((key.sk.get('Doctor:1') as never[])[t - 1])).toBe(g1ToHex(acc));
    }
  });

  it('the third component is g^-sigma_y', () => {
    const { key, witness } = keygen(msk, ['Doctor:1'], rng, 'third');
    const sigma = witness.sigma.get('Doctor:1') as bigint;
    expect(g1ToHex((key.sk.get('Doctor:1') as never[])[2])).toBe(g1ToHex(g1Pow(g1, mod(-sigma))));
  });

  it('two keys for the same attributes get different randomizers', () => {
    const a = keygen(msk, ['Doctor:1'], rng, 'alice');
    const b = keygen(msk, ['Doctor:1'], rng, 'bob');
    expect(a.witness.Br[0]).not.toBe(b.witness.Br[0]);
    expect(g1ToHex((a.key.sk.get('Doctor:1') as never[])[0])).not.toBe(
      g1ToHex((b.key.sk.get('Doctor:1') as never[])[0]),
    );
  });

  it('key size is linear in the number of indexed labels', () => {
    const one = keygen(msk, ['A:1'], rng, 'k1');
    const three = keygen(msk, ['A:1', 'A:2', 'A:3'], rng, 'k3');
    expect(one.key.sk.size).toBe(1);
    expect(three.key.sk.size).toBe(3);
  });
});

describe('end-to-end correctness over the whole policy zoo', () => {
  const cases: { name: string; policy: () => PolicyNode; holders: { has: string[]; ok: boolean }[] }[] = [
    {
      name: '(Doctor AND Cardiology) OR Emergency',
      policy: () => or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]),
      holders: [
        { has: ['Doctor', 'Cardiology'], ok: true },
        { has: ['Emergency'], ok: true },
        { has: ['Doctor'], ok: false },
        { has: ['Nurse'], ok: false },
        { has: ['Cardiology'], ok: false },
      ],
    },
    {
      name: '2-of-3',
      policy: () => threshold(2, [attr('Doctor'), attr('Cardiology'), attr('OnCall')]),
      holders: [
        { has: ['Doctor', 'OnCall'], ok: true },
        { has: ['Cardiology', 'OnCall'], ok: true },
        { has: ['Doctor', 'Cardiology', 'OnCall'], ok: true },
        { has: ['Doctor'], ok: false },
        { has: [], ok: false },
      ],
    },
    {
      name: '3-of-4 under an AND',
      policy: () =>
        and([attr('Staff'), threshold(3, [attr('A'), attr('B'), attr('C'), attr('D')])]),
      holders: [
        { has: ['Staff', 'B', 'C', 'D'], ok: true },
        { has: ['Staff', 'A', 'C'], ok: false },
        { has: ['A', 'B', 'C'], ok: false },
      ],
    },
    {
      name: 'reused attribute (one-use transform in play)',
      policy: () =>
        or([and([attr('Doctor'), attr('Cardiology')]), and([attr('Doctor'), attr('Emergency')])]),
      holders: [
        { has: ['Doctor', 'Emergency'], ok: true },
        { has: ['Doctor', 'Cardiology'], ok: true },
        { has: ['Cardiology', 'Emergency'], ok: false },
      ],
    },
  ];

  for (const { name, policy, holders } of cases) {
    it(`round-trips ${name}`, () => {
      const { pk, msk } = setup(seededRandom(`e2e:${name}`));
      const p = policy();
      const msp = policyToMsp(p);
      const { element: message } = randomGT(rng, name);
      const { ciphertext } = encrypt(pk, p, msp, message, rng, name);

      holders.forEach(({ has, ok }, idx) => {
        // Expand held names into every indexed copy the policy uses.
        const labels = msp.rows.filter((r) => has.includes(r.name)).map((r) => r.label);
        const { key } = keygen(msk, labels, rng, `${name}#${idx}`);
        const result = decrypt(ciphertext, key);
        expect(result.ok, `${has.join('+')} against ${name}`).toBe(ok);
        if (result.ok) {
          expect(gtEquals(result.recovered, message)).toBe(true);
        } else {
          expect(result.code).toBe('POLICY_UNSATISFIED');
          expect(result.detail).toMatch(/ATTR_MISSING|THRESHOLD_NOT_MET/);
        }
      });
    });
  }

  it('a wrong-but-satisfying-looking key never yields the message', () => {
    const { pk, msk } = setup(seededRandom('e2e:wrongkey'));
    const p = or([attr('Doctor'), attr('Nurse')]);
    const msp = policyToMsp(p);
    const { element: message } = randomGT(rng, 'wrongkey');
    const { ciphertext } = encrypt(pk, p, msp, message, rng, 'wrongkey');
    // A key issued by a DIFFERENT authority holds the right labels and fails.
    const other = setup(seededRandom('e2e:otherauthority'));
    const { key } = keygen(other.msk, ['Doctor:1'], rng, 'foreign');
    const result = decrypt(ciphertext, key);
    expect(result.ok).toBe(true);
    if (result.ok) expect(gtEquals(result.recovered, message)).toBe(false);
  });
});

describe('decryption failure names the actual cause', () => {
  it('reports the unsatisfied rows for a missing attribute', () => {
    const { pk, msk } = setup(seededRandom('fail:attr'));
    const p = and([attr('Doctor'), attr('Cardiology')]);
    const msp = policyToMsp(p);
    const { ciphertext } = encrypt(pk, p, msp, randomGT(rng, 'f1').element, rng, 'f1');
    const { key } = keygen(msk, ['Doctor:1'], rng, 'f1');
    const r = decrypt(ciphertext, key);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.unsatisfiedRows).toEqual([2]);
      expect(r.detail).toContain('THRESHOLD_NOT_MET');
    }
  });

  it('reports a threshold shortfall with counts', () => {
    const { pk, msk } = setup(seededRandom('fail:thr'));
    const p = threshold(2, [attr('A'), attr('B'), attr('C')]);
    const msp = policyToMsp(p);
    const { ciphertext } = encrypt(pk, p, msp, randomGT(rng, 'f2').element, rng, 'f2');
    const { key } = keygen(msk, ['A:1'], rng, 'f2');
    const r = decrypt(ciphertext, key);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('needed 2 satisfied inputs and had 1');
  });

  it('an empty key fails closed', () => {
    const { pk, msk } = setup(seededRandom('fail:empty'));
    const p = attr('Doctor');
    const msp = policyToMsp(p);
    const { ciphertext } = encrypt(pk, p, msp, randomGT(rng, 'f3').element, rng, 'f3');
    const { key } = keygen(msk, [], rng, 'f3');
    expect(decrypt(ciphertext, key).ok).toBe(false);
  });
});

describe('collusion -- the climax', () => {
  const { pk, msk } = setup(seededRandom('collusion'));
  const policy = and([attr('Doctor'), attr('Cardiology')]);
  const msp = policyToMsp(policy);
  const { element: message } = randomGT(rng, 'collusion');
  const { ciphertext, witness: ctWitness } = encrypt(pk, policy, msp, message, rng, 'collusion');

  const bob = issue(msk, 'Bob', ['Doctor:1']);
  const eve = issue(msk, 'Eve', ['Cardiology:1']);
  const alice = issue(msk, 'Alice', ['Doctor:1', 'Cardiology:1']);

  it('neither colluder can decrypt alone', () => {
    expect(decrypt(ciphertext, bob.key).ok).toBe(false);
    expect(decrypt(ciphertext, eve.key).ok).toBe(false);
  });

  it('one coherent key holding both attributes succeeds', () => {
    const r = decrypt(ciphertext, alice.key);
    expect(r.ok).toBe(true);
    if (r.ok) expect(gtEquals(r.recovered, message)).toBe(true);
  });

  it('the pooled key satisfies the policy -- and still decrypts to garbage', () => {
    const pooled = poolKeys(bob, eve);
    const r = decrypt(ciphertext, pooled.key);
    // The policy check passes. Nothing rejects the key. It simply opens wrong.
    expect(r.ok).toBe(true);
    if (r.ok) expect(gtEquals(r.recovered, message)).toBe(false);
  });

  it('both splice directions fail', () => {
    for (const [a, b] of [
      [bob, eve],
      [eve, bob],
    ] as const) {
      const r = decrypt(ciphertext, poolKeys(a, b).key);
      expect(r.ok).toBe(true);
      if (r.ok) expect(gtEquals(r.recovered, message)).toBe(false);
    }
  });

  it('the residual predicted from the r values matches the one decryption produced', () => {
    const witnesses = new Map([
      ['Bob', bob.witness],
      ['Eve', eve.witness],
    ]);
    const analysis = analyseCollusion(ciphertext, poolKeys(bob, eve), witnesses, ctWitness);
    expect(analysis.satisfiedPolicy).toBe(true);
    expect(analysis.residualIsOne).toBe(false);
    // Two independent routes to the same group element. This is the exhibit's claim.
    expect(analysis.routesAgree).toBe(true);
  });

  it('for a coherent key the same residual is exactly 1', () => {
    const witnesses = new Map([['Alice', alice.witness]]);
    const analysis = analyseCollusion(
      ciphertext,
      poolKeys(alice, alice),
      witnesses,
      ctWitness,
    );
    expect(analysis.residualIsOne).toBe(true);
    expect(analysis.routesAgree).toBe(true);
    expect(analysis.rows.every((r) => r.coherent)).toBe(true);
    expect(analysis.rows.every((r) => r.brDelta.every((d) => d === 0n))).toBe(true);
  });

  it('the borrowed row is exactly the one with a non-zero Br delta', () => {
    const witnesses = new Map([
      ['Bob', bob.witness],
      ['Eve', eve.witness],
    ]);
    const analysis = analyseCollusion(ciphertext, poolKeys(bob, eve), witnesses, ctWitness);
    const borrowed = analysis.rows.filter((r) => !r.coherent);
    expect(borrowed.map((r) => r.label)).toEqual(['Cardiology:1']);
    expect(borrowed[0].brDelta.some((d) => d !== 0n)).toBe(true);
    expect(analysis.rows.filter((r) => r.coherent).every((r) => r.brDelta.every((d) => d === 0n))).toBe(true);
  });

  it('predictedResidual is 1 exactly when every row shares the base witness', () => {
    const p = or([attr('Doctor'), attr('Nurse')]);
    const m2 = policyToMsp(p);
    const { ciphertext: c2, witness: w2 } = encrypt(pk, p, m2, randomGT(rng, 'pr').element, rng, 'pr');
    const rec = reconstruct(p, m2, new Set(['Doctor:1']));
    const same = predictedResidual(c2, rec, bob.witness, () => bob.witness, w2);
    expect(gtEquals(same, GT_ONE)).toBe(true);
    const mixed = predictedResidual(c2, rec, bob.witness, () => eve.witness, w2);
    expect(gtEquals(mixed, GT_ONE)).toBe(false);
  });
});

describe('escrow -- what msk actually grants', () => {
  it('msk is not a decryption key; it mints one, and then that key decrypts', () => {
    const { pk, msk } = setup(seededRandom('escrow'));
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    const msp = policyToMsp(policy);
    const { element: message } = randomGT(rng, 'escrow');
    const { ciphertext } = encrypt(pk, policy, msp, message, rng, 'escrow');

    // Step 1: choose a satisfying attribute set and mint a key for it.
    const labels = minimalSatisfyingLabels(policy, msp);
    expect(labels).toEqual(['Doctor:1', 'Cardiology:1']);
    const { key } = keygen(msk, labels, rng, 'authority');

    // Step 2: decrypt with that key, like any other key.
    const r = decrypt(ciphertext, key);
    expect(r.ok).toBe(true);
    if (r.ok) expect(gtEquals(r.recovered, message)).toBe(true);
  });

  it('works for a threshold policy too', () => {
    const { pk, msk } = setup(seededRandom('escrow:thr'));
    const policy = threshold(2, [attr('A'), attr('B'), attr('C')]);
    const msp = policyToMsp(policy);
    const { element: message } = randomGT(rng, 'escrow2');
    const { ciphertext } = encrypt(pk, policy, msp, message, rng, 'escrow2');
    const { key } = keygen(msk, minimalSatisfyingLabels(policy, msp), rng, 'authority2');
    const r = decrypt(ciphertext, key);
    expect(r.ok && gtEquals(r.recovered, message)).toBe(true);
  });
});

describe('NEG-1 -- no revocation', () => {
  it('a key revoked before the ciphertext existed still decrypts it', () => {
    const { pk, msk } = setup(seededRandom('neg1'));
    const policy = attr('Doctor');
    const msp = policyToMsp(policy);
    const { key } = keygen(msk, ['Doctor:1'], rng, 'revoked-user');

    // "Revocation" happens here: the authority strikes the user off its list.
    // Nothing about the key, the public key or the scheme changes.
    const revokedAt = Date.now();
    expect(revokedAt).toBeGreaterThan(0);

    // A ciphertext created AFTER the revocation, under the same public key.
    const { element: message } = randomGT(rng, 'neg1');
    const { ciphertext } = encrypt(pk, policy, msp, message, rng, 'neg1');

    const r = decrypt(ciphertext, key);
    expect(r.ok).toBe(true);
    if (r.ok) expect(gtEquals(r.recovered, message)).toBe(true);
  });

  it('the only thing that stops the revoked key is a different authority', () => {
    const first = setup(seededRandom('neg1:a'));
    const second = setup(seededRandom('neg1:b'));
    const policy = attr('Doctor');
    const msp = policyToMsp(policy);
    const { key } = keygen(first.msk, ['Doctor:1'], rng, 'old');
    const { element: message } = randomGT(rng, 'neg1b');
    const { ciphertext } = encrypt(second.pk, policy, msp, message, rng, 'neg1b');
    const r = decrypt(ciphertext, key);
    expect(r.ok).toBe(true);
    if (r.ok) expect(gtEquals(r.recovered, message)).toBe(false);
  });
});
