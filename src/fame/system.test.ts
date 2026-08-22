/**
 * The hybrid pipeline end to end: FAME-KEM -> HKDF-SHA-256 -> AES-256-GCM,
 * plus every exhibit the page ships, driven without a browser.
 */
import { describe, expect, it } from 'vitest';
import { g1, g1Pow, g2, gtEquals, gtToHex, pairing, pairingCount, resetPairingCount } from './bls';
import {
  DIAGNOSTIC_CODES,
  FAILURE_CODES,
  FAILURE_CODE_IDS,
  INTERNAL_CODES,
  SUCCESS_CODE,
  VERDICT_CODES,
} from './codes';
import { deriveAesKey, openRecord, sealRecord, toHex } from './kem';
import { and, attr, or, threshold } from './policy';
import { seededRandom } from './rand';
import {
  attemptCollusion,
  attemptOpen,
  createLab,
  escrowOpen,
  issueAll,
  issueKey,
  observePolicy,
  previewReconstruction,
  rowCoverage,
  sealUnder,
  staleAttributes,
  type KeyRecord,
  type LabState,
} from './system';
import { randomGT } from './fame';

const RECORD = 'MRN 00-4417 | Ward 3B | Troponin I 0.42 ng/mL';

function lab(seed: string): LabState {
  return createLab(seededRandom(`system:${seed}`));
}

function keyOf(state: LabState, name: string): KeyRecord {
  const k = state.keys.get(name);
  if (!k) throw new Error(`no key for ${name}`);
  return k;
}

describe('failure codes are a closed, exported set', () => {
  it('every code is one of verdict, diagnostic or internal', () => {
    expect(FAILURE_CODE_IDS.sort()).toEqual(
      [
        'ATTRIBUTE_REUSED',
        'ATTR_MISSING',
        'COLLUSION_BLOCKED',
        'MALFORMED_POLICY',
        'POLICY_UNSATISFIED',
        'THRESHOLD_NOT_MET',
      ].sort(),
    );
    for (const id of FAILURE_CODE_IDS) {
      expect(FAILURE_CODES[id].id).toBe(id);
      expect(['verdict', 'diagnostic', 'internal']).toContain(FAILURE_CODES[id].surface);
      expect(FAILURE_CODES[id].meaning.length).toBeGreaterThan(40);
    }
  });

  it('ATTRIBUTE_REUSED is internal and is the only internal code', () => {
    expect(INTERNAL_CODES).toEqual(['ATTRIBUTE_REUSED']);
    expect(VERDICT_CODES).not.toContain('ATTRIBUTE_REUSED');
    expect(DIAGNOSTIC_CODES).not.toContain('ATTRIBUTE_REUSED');
  });
});

describe('the hybrid pipeline', () => {
  it('round-trips the record through KEM, KDF and AEAD', async () => {
    const state = lab('hybrid');
    const policy = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);

    const alice = await attemptOpen(env, keyOf(state, 'Alice'));
    expect(alice.outcome).toBe('opened');
    expect(alice.code).toBe(SUCCESS_CODE.id);
    expect(alice.plaintext).toBe(RECORD);
    expect(alice.recoveredMatches).toBe(true);
    expect(alice.aeadAccepted).toBe(true);
  });

  it('the sealed bytes are not the record and are AEAD-sized', async () => {
    const state = lab('sizes');
    const policy = attr('Doctor');
    observePolicy(state, policy);
    const env = await sealUnder(state, policy, RECORD);
    // GCM adds a 16-byte tag and nothing else.
    expect(env.sealed.ciphertext.length).toBe(new TextEncoder().encode(RECORD).length + 16);
    expect(env.sealed.nonce.length).toBe(12);
    expect(toHex(env.sealed.ciphertext)).not.toContain(toHex(new TextEncoder().encode('Troponin')));
  });

  it('the AES key is a function of the encapsulated element and nothing else', async () => {
    const rng = seededRandom('kdf');
    const a = randomGT(rng, 'a').element;
    const b = randomGT(rng, 'b').element;
    const ka = await deriveAesKey(a);
    const kb = await deriveAesKey(b);
    const ka2 = await deriveAesKey(a);
    expect(toHex(ka.rawKey)).toBe(toHex(ka2.rawKey));
    expect(toHex(ka.rawKey)).not.toBe(toHex(kb.rawKey));
    expect(ka.rawKey.length).toBe(32);
    expect(ka.ikm.length).toBe(576);
  });

  it('the policy string is bound as AAD, so a relabelled envelope will not open', async () => {
    const rng = seededRandom('aad');
    const k = randomGT(rng, 'aad').element;
    const sealed = await sealRecord(k, RECORD, '(Doctor AND Cardiology)', rng);
    expect((await openRecord(k, sealed)).ok).toBe(true);
    const relabelled = { ...sealed, aad: '(Doctor OR Cardiology)' };
    const opened = await openRecord(k, relabelled);
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.reason).toBe('AEAD_TAG_REJECTED');
  });

  it('a single flipped ciphertext byte is rejected by the tag', async () => {
    const rng = seededRandom('flip');
    const k = randomGT(rng, 'flip').element;
    const sealed = await sealRecord(k, RECORD, 'policy', rng);
    const tampered = { ...sealed, ciphertext: Uint8Array.from(sealed.ciphertext) };
    tampered.ciphertext[0] ^= 0x01;
    expect((await openRecord(k, tampered)).ok).toBe(false);
  });
});

describe('the cast, against (Doctor AND Cardiology) OR Emergency', () => {
  it('two succeed and three fail, and each failure names its cause', async () => {
    const state = lab('cast');
    const policy = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);

    const results = new Map<string, Awaited<ReturnType<typeof attemptOpen>>>();
    for (const p of state.people) results.set(p.name, await attemptOpen(env, keyOf(state, p.name)));

    expect(results.get('Alice')?.outcome).toBe('opened');
    expect(results.get('Carol')?.outcome).toBe('opened');
    expect(results.get('Bob')?.outcome).toBe('denied');
    expect(results.get('Dan')?.outcome).toBe('denied');
    expect(results.get('Eve')?.outcome).toBe('denied');

    for (const name of ['Bob', 'Dan', 'Eve']) {
      const r = results.get(name);
      expect(r?.code).toBe('POLICY_UNSATISFIED');
      expect(r?.detail).toMatch(/ATTR_MISSING|THRESHOLD_NOT_MET/);
      expect(r?.plaintext).toBeNull();
    }
  });

  it('names the unsatisfied rows, and they are the rows the key does not hold', async () => {
    const state = lab('rows');
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    const bob = await attemptOpen(env, keyOf(state, 'Bob'));
    expect(bob.unsatisfiedRows).toEqual([2]);

    const coverage = rowCoverage(env, keyOf(state, 'Bob'));
    expect(coverage.get(1)).toBe(true);
    expect(coverage.get(2)).toBe(false);
    // Independent cross-check: the rows the coverage map calls false are
    // exactly the rows the attempt reported.
    expect([...coverage].filter(([, ok]) => !ok).map(([i]) => i)).toEqual([...bob.unsatisfiedRows]);
  });
});

describe('threshold gate', () => {
  it('2-of-3 opens for any two and closes for one', async () => {
    const state = lab('threshold');
    const policy = threshold(2, [attr('Doctor'), attr('Cardiology'), attr('OnCall')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);

    const alice = await attemptOpen(env, keyOf(state, 'Alice')); // Doctor + Cardiology
    expect(alice.outcome).toBe('opened');
    expect(alice.reconstruction.lagrangeSteps[0].points).toEqual([1, 2]);
    expect(alice.reconstruction.lagrangeSteps[0].basis).toEqual([2n, expect.any(BigInt)]);

    const bob = await attemptOpen(env, keyOf(state, 'Bob')); // Doctor only
    expect(bob.outcome).toBe('denied');
    expect(bob.detail).toContain('needed 2 satisfied inputs and had 1');
  });

  it('the reconstruction preview agrees with what decryption used', async () => {
    const state = lab('preview');
    const policy = threshold(2, [attr('Doctor'), attr('Cardiology'), attr('OnCall')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    const alice = keyOf(state, 'Alice');
    const preview = previewReconstruction(env, alice.issued.key.labels);
    const attempt = await attemptOpen(env, alice);
    expect([...preview.coefficients]).toEqual([...attempt.reconstruction.coefficients]);
  });
});

describe('collusion', () => {
  it('Bob + Eve satisfy the policy jointly and are still blocked, both directions', async () => {
    const state = lab('collude');
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);

    expect((await attemptOpen(env, keyOf(state, 'Bob'))).outcome).toBe('denied');
    expect((await attemptOpen(env, keyOf(state, 'Eve'))).outcome).toBe('denied');

    const outcomes = await attemptCollusion(state, env, keyOf(state, 'Bob'), keyOf(state, 'Eve'));
    expect(outcomes).toHaveLength(2);
    for (const { attempt, analysis } of outcomes) {
      // The policy check PASSES. That is the whole point.
      expect(analysis.satisfiedPolicy).toBe(true);
      expect(attempt.reconstruction.satisfied).toBe(true);
      // Decryption runs and returns a group element -- just the wrong one.
      expect(attempt.recovered).not.toBeNull();
      expect(attempt.recoveredMatches).toBe(false);
      expect(attempt.outcome).toBe('blocked');
      expect(attempt.code).toBe('COLLUSION_BLOCKED');
      expect(attempt.plaintext).toBeNull();
      // Two independent routes to the leftover blinding factor agree.
      expect(analysis.routesAgree).toBe(true);
      expect(analysis.residualIsOne).toBe(false);
      // Exactly one borrowed row, and it is the one with a non-zero Br delta.
      const borrowed = analysis.rows.filter((r) => !r.coherent);
      expect(borrowed).toHaveLength(1);
      expect(borrowed[0].brDelta.some((d) => d !== 0n)).toBe(true);
      for (const own of analysis.rows.filter((r) => r.coherent)) {
        expect(own.brDelta).toEqual([0n, 0n, 0n]);
      }
    }
  });

  it('a coherent key run through the same analysis leaves a residual of exactly 1', async () => {
    const state = lab('coherent');
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    const alice = keyOf(state, 'Alice');
    const outcomes = await attemptCollusion(state, env, alice, alice);
    for (const { attempt, analysis } of outcomes) {
      expect(analysis.residualIsOne).toBe(true);
      expect(analysis.routesAgree).toBe(true);
      expect(attempt.outcome).toBe('opened');
    }
  });

  it('re-issuing Bob a key changes his randomizer, so the residual changes too', async () => {
    const state = lab('reissue');
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    const before = (await attemptCollusion(state, env, keyOf(state, 'Bob'), keyOf(state, 'Eve')))[0];
    issueKey(state, state.people.find((p) => p.name === 'Bob') as never);
    const after = (await attemptCollusion(state, env, keyOf(state, 'Bob'), keyOf(state, 'Eve')))[0];
    expect(gtToHex(before.analysis.residualPredicted)).not.toBe(
      gtToHex(after.analysis.residualPredicted),
    );
    expect(after.attempt.outcome).toBe('blocked');
  });
});

describe('escrow -- THREAT-1', () => {
  it('is two steps: mint a satisfying key, then decrypt with it', async () => {
    const state = lab('escrow');
    const policy = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    observePolicy(state, policy);
    const env = await sealUnder(state, policy, RECORD);

    const outcome = await escrowOpen(state, env);
    // Step 1 produced an attribute set, not a plaintext.
    expect(outcome.mintedLabels).toEqual(['Doctor:1', 'Cardiology:1']);
    expect(outcome.keyElements).toBe(3 + 3 * 2 + 3);
    // Step 2 is an ordinary decryption with an ordinary key.
    expect(outcome.attempt.outcome).toBe('opened');
    expect(outcome.attempt.plaintext).toBe(RECORD);
  });

  it('works for a policy no enrolled person satisfies', async () => {
    const state = lab('escrow2');
    const policy = and([attr('Research'), attr('OnCall')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    for (const p of state.people) {
      expect((await attemptOpen(env, keyOf(state, p.name))).outcome).toBe('denied');
    }
    expect((await escrowOpen(state, env)).attempt.outcome).toBe('opened');
  });
});

describe('NEG-1 -- no revocation', () => {
  it('a revoked key opens a record sealed AFTER the revocation', async () => {
    const state = lab('neg1');
    const policy = attr('Doctor');
    observePolicy(state, policy);
    issueAll(state);
    const bob = keyOf(state, 'Bob');

    // Revocation, in full: a boolean on the authority's staff list.
    const person = state.people.find((p) => p.name === 'Bob') as { revoked: boolean };
    person.revoked = true;
    expect(person.revoked).toBe(true);

    // A NEW envelope, sealed after the revocation, under the same public key.
    const env = await sealUnder(state, policy, 'Sealed after Bob was revoked');
    const attempt = await attemptOpen(env, bob);

    expect(attempt.outcome).toBe('opened');
    expect(attempt.plaintext).toBe('Sealed after Bob was revoked');
    // Nothing about the key material changed when the flag flipped.
    expect(bob.issued.key.labels).toEqual(['Doctor:1']);
  });

  it('the only thing that shuts the revoked key out is a whole new authority', async () => {
    const first = lab('neg1a');
    const policy = attr('Doctor');
    observePolicy(first, policy);
    issueAll(first);
    const bob = keyOf(first, 'Bob');

    const second = lab('neg1b');
    observePolicy(second, policy);
    const env = await sealUnder(second, policy, 'Sealed under a fresh authority');
    const attempt = await attemptOpen(env, bob);
    // Decryption still runs -- the labels match -- but the element is wrong.
    expect(attempt.reconstruction.satisfied).toBe(true);
    expect(attempt.recoveredMatches).toBe(false);
    expect(attempt.outcome).toBe('blocked');
    expect(attempt.plaintext).toBeNull();
  });
});

describe('the one-use transform is enforced on both sides', () => {
  it('a policy that reuses Doctor grows every Doctor key', async () => {
    const state = lab('oneuse');
    const simple = or([attr('Doctor'), attr('Nurse')]);
    observePolicy(state, simple);
    issueAll(state);
    const before = keyOf(state, 'Bob');
    expect(before.issued.key.labels).toEqual(['Doctor:1']);
    expect(before.elements).toBe(3 + 3 + 3);

    const reusing = or([
      and([attr('Doctor'), attr('Cardiology')]),
      and([attr('Doctor'), attr('Emergency')]),
    ]);
    const growth = observePolicy(state, reusing);
    expect(growth).toEqual([{ name: 'Doctor', from: 1, to: 2 }]);

    // Bob's existing key is now stale, and the page must say so rather than
    // quietly re-issuing: FAME fixes k at set-up, so raising it invalidates keys.
    expect(staleAttributes(state, before)).toEqual(['Doctor']);

    const env = await sealUnder(state, reusing, RECORD);
    const staleAttempt = await attemptOpen(env, before);
    expect(staleAttempt.outcome).toBe('denied');
    expect(staleAttempt.detail).toContain('Doctor:2');

    // Re-issued at the new k, Alice can open it; her key really did grow.
    const alice = state.people.find((p) => p.name === 'Alice') as never;
    const reissued = issueKey(state, alice);
    expect(reissued.issued.key.labels).toEqual(['Doctor:1', 'Doctor:2', 'Cardiology:1']);
    expect(reissued.elements).toBeGreaterThan(3 + 3 * 2 + 3);
    expect((await attemptOpen(env, reissued)).outcome).toBe('opened');
  });

  it('key size grows exactly by a factor of k, as the paper states', () => {
    const state = lab('growth');
    observePolicy(state, or([attr('Doctor'), attr('Nurse')]));
    const one = issueKey(state, { name: 'X', attributes: ['Doctor'], revoked: false });
    observePolicy(state, and([attr('Doctor'), attr('Doctor'), attr('Doctor')]));
    const three = issueKey(state, { name: 'Y', attributes: ['Doctor'], revoked: false });
    // Only the per-attribute components scale; sk0 and sk' are fixed at 3 each.
    const perAttribute = (r: KeyRecord): number => r.elements - 6;
    expect(perAttribute(three)).toBe(3 * perAttribute(one));
  });
});

describe('decryption costs six pairings, whatever the policy looks like', () => {
  it('is exactly 6 for a small policy and for one twice the size', async () => {
    const state = lab('pairings');
    const small = or([and([attr('Doctor'), attr('Cardiology')]), attr('Emergency')]);
    // 3-of-6 over the same attribute: six rows, three columns, and the
    // one-use transform pushes Doctor to k = 6 so a holder's key grows too.
    const wide = threshold(3, Array.from({ length: 6 }, () => attr('Doctor')));
    observePolicy(state, small);
    observePolicy(state, wide);
    issueAll(state);

    const smallEnv = await sealUnder(state, small, RECORD);
    const wideEnv = await sealUnder(state, wide, RECORD);
    expect(smallEnv.msp.rows.length).toBe(3);
    expect(wideEnv.msp.rows.length).toBe(6);
    // The wide policy also has more COLUMNS, so encryption really did do more
    // work -- which is the contrast that makes the constant meaningful.
    expect(wideEnv.msp.columns).toBeGreaterThan(smallEnv.msp.columns);

    const alice = keyOf(state, 'Alice');
    const a = await attemptOpen(smallEnv, alice);
    const b = await attemptOpen(wideEnv, alice);
    expect(a.outcome).toBe('opened');
    expect(b.outcome).toBe('opened');
    expect(a.pairings).toBe(6);
    expect(b.pairings).toBe(6);
  });

  it('is 0 when the policy check fails, because decryption never runs', async () => {
    const state = lab('pairings-fail');
    const policy = and([attr('Doctor'), attr('Cardiology')]);
    observePolicy(state, policy);
    issueAll(state);
    const env = await sealUnder(state, policy, RECORD);
    const bob = await attemptOpen(env, keyOf(state, 'Bob'));
    expect(bob.outcome).toBe('denied');
    expect(bob.pairings).toBe(0);
  });

  it('the counter counts real pairings only, not the identity short-circuit', () => {
    resetPairingCount();
    expect(pairingCount()).toBe(0);
    pairing(g1, g2);
    expect(pairingCount()).toBe(1);
    // An identity input returns 1 without computing anything.
    pairing(g1Pow(g1, 0n), g2);
    expect(pairingCount()).toBe(1);
  });
});

describe('the encapsulated element', () => {
  it('is a real GT element, not bytes pretending to be one', async () => {
    const state = lab('gt');
    const policy = attr('Doctor');
    observePolicy(state, policy);
    const env = await sealUnder(state, policy, RECORD);
    // 576 bytes of Fp12, and it is in the order-p subgroup: raising it to p
    // gives the identity.
    expect(gtToHex(env.witness.encapsulated).length).toBe(1152);
    const order = (await import('./bls')).ORDER;
    const { gtPow, GT_ONE } = await import('./bls');
    expect(gtEquals(gtPow(env.witness.encapsulated, order), GT_ONE)).toBe(true);
  });
});
