/**
 * The pinned-vector suite.
 *
 * This is the lab's independent verifier. It does two jobs the round-trip
 * tests cannot do:
 *
 *  1. FIXTURE MATCH. Regenerate every vector from the seed and compare it to
 *     vectors/fame-vectors.json byte for byte. Any change to the scheme, the
 *     hash-input encoding, the MSP conversion or the KEM parameters moves at
 *     least one element and fails here.
 *
 *  2. INDEPENDENT RE-DERIVATION. Rebuild the scheme's group elements straight
 *     from the seed's scalars using only the pairing and field helpers -- never
 *     calling setup, keygen, encrypt or decrypt -- and check the pairing
 *     equations against the PINNED hex. A test that re-runs the implementation
 *     it is checking will happily agree with a bug; this one would not.
 *
 * The seeded source is label-addressed rather than sequential, so this file can
 * ask for `a1` or `r1@Bob` directly without replaying the scheme's call order.
 * That is what makes an independent route possible at all.
 *
 * Every element in the fixture carries its group tag (G1, G2, GT or Zp), and
 * `tags are self-consistent` below checks the tag against the encoded width.
 * The typing is the thing the first revision of this lab's plan got wrong:
 * BSW07 needs one element on both sides of a symmetric pairing, BLS12-381 is
 * Type-3, and a tag that has to be two things at once is the tell.
 */
import { readFileSync, writeFileSync } from 'node:fs';
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
  g1FromHex,
  g1Inv,
  g1Mul,
  g1Pow,
  g1Product,
  g1ToHex,
  g2,
  g2FromHex,
  g2Pow,
  g2ToHex,
  gtDiv,
  gtEquals,
  gtFromHex,
  gtMul,
  gtPow,
  gtProduct,
  gtToHex,
  hashAttribute,
  hashColumn,
  mod,
  mulMod,
  pairing,
  type G1Point,
  type TaggedElement,
} from './bls';
import { seededRandom } from './rand';
import { buildVectorFixture, VECTOR_SEED, vectorPolicy, type VectorFixture } from './vectors';
import { policyToMsp } from './msp';
import { assertInjective } from './oneuse';
import { PolicyError } from './policy';

const FIXTURE_PATH = new URL('../../vectors/fame-vectors.json', import.meta.url);

function loadFixture(): VectorFixture {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as VectorFixture;
}

const built = await buildVectorFixture();

// `UPDATE_VECTORS=1 npm test` rewrites the fixture. The default path only ever
// compares -- a gate that regenerates its own expectations gates nothing.
if (process.env.UPDATE_VECTORS === '1') {
  writeFileSync(FIXTURE_PATH, `${JSON.stringify(built, null, 2)}\n`);
}

const pinned = loadFixture();
const rng = seededRandom(VECTOR_SEED);

/* -------------------------------------------------------------------------- */
/* 1. Fixture match                                                           */
/* -------------------------------------------------------------------------- */

describe('pinned vectors', () => {
  it('regenerate from the seed byte for byte', () => {
    expect(JSON.parse(JSON.stringify(built))).toEqual(pinned);
  });

  // A full second build is ~10s of pairings; the point is that nothing in the
  // pipeline depends on call order or on a warm hash cache.
  it('are deterministic across two independent builds', { timeout: 120_000 }, async () => {
    const again = await buildVectorFixture();
    expect(JSON.stringify(again)).toBe(JSON.stringify(built));
  });

  it('publish every element with its group tag, and the tag matches the width', () => {
    const widths: Record<string, number> = {
      G1: G1_BYTES * 2,
      G2: G2_BYTES * 2,
      GT: GT_BYTES * 2,
      Zp: 64,
    };
    let checked = 0;
    const walk = (node: unknown, path: string): void => {
      if (node === null || typeof node !== 'object') return;
      const obj = node as Record<string, unknown>;
      if (typeof obj.group === 'string' && typeof obj.hex === 'string') {
        const e = node as TaggedElement;
        expect(widths[e.group], `${path} has unknown tag ${e.group}`).toBeDefined();
        expect(e.hex.length, `${path} tagged ${e.group}`).toBe(widths[e.group]);
        expect(/^[0-9a-f]*$/.test(e.hex), `${path} is lowercase hex`).toBe(true);
        checked += 1;
        return;
      }
      for (const [k, v] of Object.entries(obj)) walk(v, `${path}.${k}`);
    };
    walk(pinned, 'fixture');
    // Setup 5 + msk 7 + five keys + ciphertext + decryptions + collusion + threshold.
    expect(checked).toBeGreaterThan(100);
  });

  it('put the ciphertext in G1/G2/GT and never the same element in two groups', () => {
    // ct0 lives in G2 (it is h raised to the encryptor's randomness); every ct
    // row lives in G1 (it is a product of hashed points). Type-3 means these
    // are different groups with no isomorphism, so no hex may appear in both.
    const g2Hex = new Set(pinned.ciphertext.ct0.map((e) => e.hex));
    const g1Hex = new Set(pinned.ciphertext.rows.flatMap((r) => r.ct.map((e) => e.hex)));
    expect(pinned.ciphertext.ct0.every((e) => e.group === 'G2')).toBe(true);
    expect(pinned.ciphertext.rows.every((r) => r.ct.every((e) => e.group === 'G1'))).toBe(true);
    for (const h of g1Hex) expect(g2Hex.has(h)).toBe(false);
  });

  it('record the one-use transform and the key growth it forces', () => {
    expect(pinned.policy.expression).toBe('((Doctor AND Cardiology) OR (Doctor AND Emergency))');
    expect(pinned.policy.reusedNames).toEqual(['Doctor']);
    const doctor = pinned.policy.transform.find((t) => t.name === 'Doctor');
    expect(doctor?.labels).toEqual(['Doctor:1', 'Doctor:2']);
    expect(pinned.policy.registry.find((r) => r.name === 'Doctor')?.copies).toBe(2);

    // Bob holds only Doctor, so his key carries BOTH indexed copies: the
    // factor-of-k growth the paper names, counted rather than asserted.
    const bob = pinned.keys.find((k) => k.holder === 'Bob');
    const carol = pinned.keys.find((k) => k.holder === 'Carol');
    expect(bob?.labels).toEqual(['Doctor:1', 'Doctor:2']);
    expect(carol?.labels).toEqual(['Emergency:1']);
    expect(bob?.keyElements).toBe(3 + 3 * 2 + 3);
    expect(carol?.keyElements).toBe(3 + 3 * 1 + 3);
  });
});

/* -------------------------------------------------------------------------- */
/* 2. Independent re-derivation                                               */
/* -------------------------------------------------------------------------- */

// Pull the secrets straight from the seed. These are the same values setup()
// and keygen() drew, obtained without running either.
const a1 = rng.nonZeroScalar('a1');
const a2 = rng.nonZeroScalar('a2');
const b1 = rng.nonZeroScalar('b1');
const b2 = rng.nonZeroScalar('b2');
const d1 = rng.scalar('d1');
const d2 = rng.scalar('d2');
const d3 = rng.scalar('d3');
const egh = pairing(g1, g2);

const brFor = (holder: string): [bigint, bigint, bigint] => {
  const r1 = rng.scalar(`r1@${holder}`);
  const r2 = rng.scalar(`r2@${holder}`);
  return [mulMod(b1, r1), mulMod(b2, r2), addMod(r1, r2)];
};

describe('independent re-derivation from the seed', () => {
  it('the pinned master secret is the seed s scalars', () => {
    expect(pinned.masterSecret.a1.hex).toBe(a1.toString(16).padStart(64, '0'));
    expect(pinned.masterSecret.a2.hex).toBe(a2.toString(16).padStart(64, '0'));
    expect(pinned.masterSecret.b1.hex).toBe(b1.toString(16).padStart(64, '0'));
    expect(pinned.masterSecret.b2.hex).toBe(b2.toString(16).padStart(64, '0'));
    expect(pinned.masterSecret.gd1.hex).toBe(g1ToHex(g1Pow(g1, d1)));
    expect(pinned.masterSecret.gd2.hex).toBe(g1ToHex(g1Pow(g1, d2)));
    expect(pinned.masterSecret.gd3.hex).toBe(g1ToHex(g1Pow(g1, d3)));
  });

  it('pk is (h, h^a1, h^a2, e(g,h)^(d1a1+d3), e(g,h)^(d2a2+d3))', () => {
    expect(pinned.publicKey.h.hex).toBe(g2ToHex(g2));
    expect(pinned.publicKey.H1.hex).toBe(g2ToHex(g2Pow(g2, a1)));
    expect(pinned.publicKey.H2.hex).toBe(g2ToHex(g2Pow(g2, a2)));
    expect(pinned.publicKey.T1.hex).toBe(gtToHex(gtPow(egh, addMod(mulMod(d1, a1), d3))));
    expect(pinned.publicKey.T2.hex).toBe(gtToHex(gtPow(egh, addMod(mulMod(d2, a2), d3))));
  });

  it('every pinned secret key is the Figure 3.1 product, rebuilt from scalars', () => {
    for (const holder of pinned.keys) {
      const Br = brFor(holder.holder);
      expect(holder.Br.map((e) => e.hex)).toEqual(Br.map((x) => x.toString(16).padStart(64, '0')));
      expect(holder.sk0.map((e) => e.hex)).toEqual(Br.map((x) => g2ToHex(g2Pow(g2, x))));

      const sigmaPrime = rng.scalar(`sigmaPrime@${holder.holder}`);
      const a: [bigint, bigint] = [a1, a2];
      const gd: [G1Point, G1Point, G1Point] = [g1Pow(g1, d1), g1Pow(g1, d2), g1Pow(g1, d3)];

      for (const t of T_INDICES) {
        const at = a[t - 1];
        const factors = L_INDICES.map((l) => g1Pow(hashColumn(1, l, t), divMod(Br[l - 1], at)));
        const expected = g1Mul(
          g1Mul(gd[t - 1], g1Product(factors)),
          g1Pow(g1, divMod(sigmaPrime, at)),
        );
        expect(holder.skPrime[t - 1].hex, `${holder.holder} sk'_${t}`).toBe(g1ToHex(expected));
      }
      expect(holder.skPrime[2].hex).toBe(
        g1ToHex(g1Mul(gd[2], g1Pow(g1Inv(g1), sigmaPrime))),
      );

      for (const label of holder.labels) {
        const sigma = rng.scalar(`sigma:${label}@${holder.holder}`);
        for (const t of T_INDICES) {
          const at = a[t - 1];
          const factors = L_INDICES.map((l) =>
            g1Pow(hashAttribute(label, l, t), divMod(Br[l - 1], at)),
          );
          const expected = g1Mul(g1Product(factors), g1Pow(g1, divMod(sigma, at)));
          expect(holder.sk[label][t - 1].hex, `${holder.holder} sk_${label},${t}`).toBe(
            g1ToHex(expected),
          );
        }
        expect(holder.sk[label][2].hex).toBe(g1ToHex(g1Pow(g1Inv(g1), sigma)));
      }
    }
  });

  it('the ciphertext is the Figure 3.1 product, rebuilt from scalars', () => {
    const s1 = rng.scalar('s1@vector');
    const s2 = rng.scalar('s2@vector');
    const s: [bigint, bigint] = [s1, s2];

    expect(pinned.ciphertext.s1.hex).toBe(s1.toString(16).padStart(64, '0'));
    expect(pinned.ciphertext.s2.hex).toBe(s2.toString(16).padStart(64, '0'));
    expect(pinned.ciphertext.ct0[0].hex).toBe(g2ToHex(g2Pow(g2Pow(g2, a1), s1)));
    expect(pinned.ciphertext.ct0[1].hex).toBe(g2ToHex(g2Pow(g2Pow(g2, a2), s2)));
    expect(pinned.ciphertext.ct0[2].hex).toBe(g2ToHex(g2Pow(g2, addMod(s1, s2))));

    const msp = policyToMsp(vectorPolicy());
    expect(msp.rows.map((r) => r.label)).toEqual(pinned.ciphertext.rows.map((r) => r.label));

    for (const row of msp.rows) {
      for (const l of L_INDICES) {
        const perT = T_INDICES.map((t) => {
          let acc = hashAttribute(row.label, l, t);
          for (let j = 1; j <= msp.columns; j++) {
            const m = row.vector[j - 1];
            if (m === 0n) continue;
            acc = g1Mul(acc, g1Pow(hashColumn(j, l, t), m));
          }
          return g1Pow(acc, s[t - 1]);
        });
        const expected = g1Mul(perT[0], perT[1]);
        expect(pinned.ciphertext.rows[row.index - 1].ct[l - 1].hex, `ct_${row.index},${l}`).toBe(
          g1ToHex(expected),
        );
      }
    }

    // ct' = e(g,h)^(s1(a1 d1 + d3) + s2(a2 d2 + d3)) * msg, computed here from
    // the raw exponents rather than from the published T1 and T2.
    const blinding = gtPow(
      egh,
      addMod(
        mulMod(s1, addMod(mulMod(a1, d1), d3)),
        mulMod(s2, addMod(mulMod(a2, d2), d3)),
      ),
    );
    const message = gtFromHex(pinned.ciphertext.message.hex);
    expect(pinned.ciphertext.ctPrime.hex).toBe(gtToHex(gtMul(blinding, message)));

    // The encapsulated element is e(g,h)^u for the seed's u.
    const u = rng.scalar('gt:vector');
    expect(pinned.ciphertext.message.hex).toBe(gtToHex(gtPow(egh, u)));
  });

  it("Alice's decryption satisfies num / den = msg, checked with pairings on the pinned hex", () => {
    const alice = pinned.keys.find((k) => k.holder === 'Alice');
    expect(alice).toBeDefined();
    if (!alice) return;
    const record = pinned.decryptions.find((d) => d.holder === 'Alice');
    expect(record?.satisfied).toBe(true);
    const gammas = new Map((record?.coefficients ?? []).map((c) => [c.row, BigInt(`0x${c.gamma.hex}`)]));
    expect(gammas.size).toBeGreaterThan(0);

    const sk0 = pinned.keys.filter((k) => k.holder === 'Alice')[0].sk0.map((e) => g2FromHex(e.hex));
    const ct0 = pinned.ciphertext.ct0.map((e) => g2FromHex(e.hex));
    const rows = pinned.ciphertext.rows;

    const num = gtMul(
      gtFromHex(pinned.ciphertext.ctPrime.hex),
      gtProduct(
        L_INDICES.map((l) =>
          pairing(
            g1Product(
              [...gammas].map(([i, g]) => g1Pow(g1FromHex(rows[i - 1].ct[l - 1].hex), g)),
            ),
            sk0[l - 1],
          ),
        ),
      ),
    );
    const den = gtProduct(
      L_INDICES.map((l) => {
        let acc = g1FromHex(alice.skPrime[l - 1].hex);
        for (const [i, g] of gammas) {
          acc = g1Mul(acc, g1Pow(g1FromHex(alice.sk[rows[i - 1].label][l - 1].hex), g));
        }
        return pairing(acc, ct0[l - 1]);
      }),
    );

    expect(gtToHex(gtDiv(num, den))).toBe(pinned.ciphertext.message.hex);
    expect(record?.recovered?.hex).toBe(pinned.ciphertext.message.hex);
    expect(record?.matchesMessage).toBe(true);
  });

  it('the pinned collusion residual is the predicted leftover blinding, from scalars', () => {
    const c = pinned.collusion;
    expect(c.base).toBe('Bob');
    expect(c.other).toBe('Eve');
    expect(c.satisfiedPolicy).toBe(true);
    expect(c.residualIsOne).toBe(false);
    expect(c.routesAgree).toBe(true);

    // Recompute the residual from the r values, the encryptor's s values and
    // the reconstruction coefficients -- no key material, no decryption.
    const s: [bigint, bigint] = [rng.scalar('s1@vector'), rng.scalar('s2@vector')];
    const brBob = brFor('Bob');
    const brEve = brFor('Eve');
    const msp = policyToMsp(vectorPolicy());
    const held = new Set(['Doctor:1', 'Doctor:2', 'Cardiology:1']);
    const usedRows = msp.rows.filter((r) => held.has(r.label));
    // The pooled key satisfies the left branch: Doctor:1 AND Cardiology:1.
    const gammas = new Map<number, bigint>([
      [1, 2n],
      [2, mod(-1n)],
    ]);
    const factors = usedRows
      .filter((r) => gammas.has(r.index))
      .flatMap((r) => {
        const owner = r.label.startsWith('Cardiology') ? brEve : brBob;
        const gamma = gammas.get(r.index) as bigint;
        return L_INDICES.flatMap((l) => {
          const delta = mod(brBob[l - 1] - owner[l - 1]);
          if (delta === 0n) return [];
          return T_INDICES.map((t) =>
            gtPow(pairing(hashAttribute(r.label, l, t), g2), mulMod(mulMod(gamma, s[t - 1]), delta)),
          );
        });
      });
    expect(gtToHex(gtProduct(factors))).toBe(c.residual.hex);

    // And the residual really is what separates the two GT elements.
    const recovered = gtFromHex(c.recovered.hex);
    const message = gtFromHex(pinned.ciphertext.message.hex);
    expect(gtToHex(gtDiv(recovered, message))).toBe(c.residual.hex);
    expect(gtEquals(gtFromHex(c.residual.hex), GT_ONE)).toBe(false);
  });

  it('the threshold vector reconstructs to (1, 0) and decrypts', () => {
    const t = pinned.threshold;
    expect(t.expression).toBe('2-of-3(Doctor, Cardiology, OnCall)');
    expect(t.columns).toBe(2);
    expect(t.rows.map((r) => r.label)).toEqual(['Doctor:1', 'Cardiology:1', 'OnCall:1']);
    // Rows are the Vandermonde evaluations (1, i).
    expect(t.rows.map((r) => BigInt(`0x${r.vector[1]}`))).toEqual([1n, 2n, 3n]);
    expect(t.heldBy).toEqual(['Doctor:1', 'OnCall:1']);

    // Lagrange at 0 over x = 1 and x = 3: 3/2 and -1/2.
    const gammas = t.coefficients.map((c) => BigInt(`0x${c.gamma.hex}`));
    expect(t.coefficients.map((c) => c.row)).toEqual([1, 3]);
    expect(gammas[0]).toBe(divMod(3n, 2n));
    expect(gammas[1]).toBe(mod(-divMod(1n, 2n)));
    // sum gamma_i M_i = (1, 0), recomputed here from the pinned rows.
    const col0 = addMod(mulMod(gammas[0], 1n), mulMod(gammas[1], 1n));
    const col1 = addMod(mulMod(gammas[0], 1n), mulMod(gammas[1], 3n));
    expect(col0).toBe(1n);
    expect(col1).toBe(0n);
    expect(t.matchesMessage).toBe(true);
  });

  it('the pinned decryption outcomes are the cast the brief describes', () => {
    const byHolder = Object.fromEntries(pinned.decryptions.map((d) => [d.holder, d]));
    expect(byHolder.Alice.satisfied).toBe(true);
    expect(byHolder.Carol.satisfied).toBe(false);
    expect(byHolder.Bob.satisfied).toBe(false);
    expect(byHolder.Dan.satisfied).toBe(false);
    expect(byHolder.Eve.satisfied).toBe(false);
    for (const d of pinned.decryptions) {
      if (!d.satisfied) expect(d.failureCode).toBe('POLICY_UNSATISFIED');
    }
    // Exactly one of the five can read it. Two-succeed-two-fail is the brief's
    // other policy; under THIS one Carol lacks Doctor, so only Alice gets in.
    expect(pinned.decryptions.filter((d) => d.satisfied).length).toBe(1);
  });
});

/* -------------------------------------------------------------------------- */
/* 3. ATTRIBUTE_REUSED -- the internal invariant                              */
/* -------------------------------------------------------------------------- */

describe('ATTRIBUTE_REUSED is an internal invariant, never a user verdict', () => {
  it('the fixture s row labelling is injective', () => {
    const labels = pinned.msp.rows.map((r) => r.label);
    expect(new Set(labels).size).toBe(labels.length);
    expect(() => assertInjective(labels)).not.toThrow();
  });

  it('assertInjective throws with the code if a duplicate ever reaches the scheme', () => {
    try {
      assertInjective(['Doctor:1', 'Cardiology:1', 'Doctor:1']);
      expect.unreachable('duplicate label must be rejected');
    } catch (e) {
      expect(e).toBeInstanceOf(PolicyError);
      expect((e as PolicyError).code).toBe('ATTRIBUTE_REUSED');
      expect((e as PolicyError).message).toContain('the one-use transform did not run or is broken');
    }
  });

  it('a policy that reuses an attribute produces distinct rows, not an error', () => {
    const msp = policyToMsp(vectorPolicy());
    expect(msp.rows.map((r) => r.label)).toEqual([
      'Doctor:1',
      'Cardiology:1',
      'Doctor:2',
      'Emergency:1',
    ]);
  });
});
