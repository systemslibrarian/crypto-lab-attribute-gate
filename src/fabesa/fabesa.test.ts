import { describe, expect, it, vi } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  addMod,
  divMod,
  g1,
  g1Mul,
  g1Pow,
  g1Product,
  g1ToHex,
  g2,
  g2Pow,
  g2ToHex,
  gtEquals,
  gtMul,
  gtPow,
  gtToHex,
  hashToG1 as fameHashToG1,
  mod,
  mulMod,
  pairing,
  pairingCount,
  resetPairingCount,
} from '../fame/bls';
import { seededRandom, type RandomSource } from '../fame/rand';
import {
  bytesToHex,
  encodeHiddenAttribute,
  type HiddenAttribute,
} from './encoding';
import {
  DEFAULT_ENUMERATION_LIMITS,
  FABESA_HASH_DST,
  FABESA_PAIRING_TERMS_PER_CANDIDATE,
  FABESA_SECURITY_SCOPE,
  decryptCandidate,
  encrypt,
  enumerateReconstructionCandidates,
  hashHiddenAttribute,
  keygen,
  publicPolicyOf,
  setup,
  type HiddenPolicy,
  type ReconstructionCandidate,
  type SecretKey,
} from './fabesa';
import { encodeEnvelopeAad, openEnvelope, sealEnvelope } from './kem';

const RECORD = 'Patient 0042 | treatment plan: private';

function single(name: string, value: string): HiddenPolicy {
  return { rows: [{ name, value, vector: [1n] }] };
}

function orPolicy(rows: readonly HiddenAttribute[]): HiddenPolicy {
  return { rows: rows.map((attribute) => ({ ...attribute, vector: [1n] })) };
}

function andPolicy(a: HiddenAttribute, b: HiddenAttribute): HiddenPolicy {
  // Shamir 2-of-2 rows. 2*M1 - M2 = (1,0).
  return {
    rows: [
      { ...a, vector: [1n, 1n] },
      { ...b, vector: [1n, 2n] },
    ],
  };
}

function onlyCandidate(
  policy: ReturnType<typeof publicPolicyOf>,
  key: SecretKey,
): ReconstructionCandidate {
  const result = enumerateReconstructionCandidates(policy, key);
  if (!result.ok || result.candidates.length !== 1) {
    throw new Error('test fixture did not produce exactly one candidate');
  }
  return result.candidates[0];
}

/** Traverse own data, including Map entries, without invoking prototypes/getters. */
function containsString(root: unknown, needle: string): boolean {
  const seen = new WeakSet<object>();
  const visit = (value: unknown): boolean => {
    if (typeof value === 'string') return value.includes(needle);
    if (value === null || typeof value !== 'object') return false;
    if (seen.has(value)) return false;
    seen.add(value);
    if (value instanceof Map) {
      for (const [mapKey, mapValue] of value) {
        if (visit(mapKey) || visit(mapValue)) return true;
      }
      return false;
    }
    for (const item of Object.values(value)) {
      if (visit(item)) return true;
    }
    return false;
  };
  return visit(root);
}

describe('canonical hidden-attribute encoding', () => {
  it('separates branch, name and value boundaries injectively', () => {
    const a = encodeHiddenAttribute(0, { name: 'AB', value: 'C' });
    const b = encodeHiddenAttribute(0, { name: 'A', value: 'BC' });
    const c = encodeHiddenAttribute(1, { name: 'AB', value: 'C' });
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    expect(bytesToHex(a)).not.toBe(bytesToHex(c));
  });

  it('rejects strings whose byte representation would not be canonical', () => {
    expect(() => encodeHiddenAttribute(0, { name: 'Cafe\u0301', value: 'x' })).toThrowError(
      /NFC-normalized/,
    );
    expect(() => encodeHiddenAttribute(0, { name: 'Role', value: '\ud800' })).toThrowError(
      /unpaired/,
    );
    expect(() => encodeHiddenAttribute(0, { name: 'Role\nAdmin', value: 'x' })).toThrowError(
      /control/,
    );
  });

  it('uses a FABESA-specific RFC 9380 DST and distinct H0/H1 points', () => {
    const attribute = { name: 'Department', value: 'Cardiology' };
    const h0 = hashHiddenAttribute(0, attribute);
    const h1 = hashHiddenAttribute(1, attribute);
    expect(FABESA_HASH_DST).toContain('FABESA-CP-A2BE');
    expect(FABESA_HASH_DST.endsWith('_XMD:SHA-256_SSWU_RO_')).toBe(true);
    expect(FABESA_HASH_DST.length).toBeLessThanOrEqual(255);
    expect(g1ToHex(h0)).not.toBe(g1ToHex(h1));
    // The same bytes under the existing FAME domain must not alias this scheme.
    expect(g1ToHex(h0)).not.toBe(g1ToHex(fameHashToG1(encodeHiddenAttribute(0, attribute))));
  });
});

describe('Figure 5 equations on real Type-3 BLS12-381 groups', () => {
  it('Setup keeps independent g3 and publishes the exact four paper values', () => {
    const rng = seededRandom('fabesa:setup-equations');
    const { pk, msk } = setup(rng);
    const alpha = rng.scalar('fabesa:alpha');
    const b1 = rng.nonZeroScalar('fabesa:b1');
    const b2 = rng.nonZeroScalar('fabesa:b2');
    const c = rng.nonZeroScalar('fabesa:g3');

    expect(msk).toEqual({ alpha, b1, b2 });
    expect(g1ToHex(pk.g3)).toBe(g1ToHex(g1Pow(g1, c)));
    expect(g1ToHex(pk.g3)).not.toBe(g1ToHex(g1));
    expect(g2ToHex(pk.B1)).toBe(g2ToHex(g2Pow(g2, b1)));
    expect(g2ToHex(pk.B2)).toBe(g2ToHex(g2Pow(g2, b2)));
    expect(gtEquals(pk.EAlpha, gtPow(pairing(g1, g2), alpha))).toBe(true);
  });

  it('KeyGen matches sk1, sk2, sk3 and sk4 independently', () => {
    const rng = seededRandom('fabesa:key-equations');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'alice');
    const r = rng.scalar('fabesa:r@alice');
    const component = key.components.get(attribute.name);
    expect(component).toBeDefined();
    if (!component) return;

    expect(g2ToHex(key.sk1)).toBe(g2ToHex(g2Pow(g2, r)));
    expect(g1ToHex(key.sk2)).toBe(
      g1ToHex(g1Mul(g1Pow(g1, msk.alpha), g1Pow(pk.g3, mod(-r)))),
    );
    expect(g1ToHex(component.sk3)).toBe(
      g1ToHex(g1Pow(hashHiddenAttribute(0, attribute), divMod(r, msk.b1))),
    );
    expect(g1ToHex(component.sk4)).toBe(
      g1ToHex(g1Pow(hashHiddenAttribute(1, attribute), divMod(r, msk.b2))),
    );
  });

  it('Encrypt exponentiates both hash terms and uses g3 for the MSP share', () => {
    const rng = seededRandom('fabesa:encrypt-equations');
    const { pk } = setup(rng);
    const policy = andPolicy(
      { name: 'Department', value: 'Cardiology' },
      { name: 'Clearance', value: 'Clinical' },
    );
    const message = gtPow(pairing(g1, g2), 91n);
    const ciphertext = encrypt(pk, policy, message, rng, 'ct');
    const s1 = rng.scalar('fabesa:s1@ct');
    const s2 = rng.scalar('fabesa:s2@ct');
    const s = addMod(s1, s2);
    const v2 = rng.scalar('fabesa:v2@ct');

    policy.rows.forEach((row, index) => {
      const share = addMod(mulMod(row.vector[0], s), mulMod(row.vector[1], v2));
      const expected = g1Product([
        g1Pow(pk.g3, share),
        g1Pow(hashHiddenAttribute(0, row), s1),
        g1Pow(hashHiddenAttribute(1, row), s2),
      ]);
      expect(g1ToHex(ciphertext.ct1[index])).toBe(g1ToHex(expected));
    });
    expect(g2ToHex(ciphertext.ct2)).toBe(g2ToHex(g2Pow(g2, s)));
    expect(g2ToHex(ciphertext.ct3)).toBe(g2ToHex(g2Pow(pk.B1, s1)));
    expect(g2ToHex(ciphertext.ct4)).toBe(g2ToHex(g2Pow(pk.B2, s2)));
    expect(gtEquals(ciphertext.ct5, gtMul(gtPow(pk.EAlpha, s), message))).toBe(true);
  });

  it('Decrypt recovers the message with four pairings and nontrivial gammas', () => {
    const rng = seededRandom('fabesa:decrypt-equations');
    const { pk, msk } = setup(rng);
    const attributes = [
      { name: 'Department', value: 'Cardiology' },
      { name: 'Clearance', value: 'Clinical' },
    ];
    const policy = andPolicy(attributes[0], attributes[1]);
    const key = keygen(pk, msk, attributes, rng, 'alice');
    const message = gtPow(pairing(g1, g2), 123456n);
    const ciphertext = encrypt(pk, policy, message, rng, 'record');
    const enumeration = enumerateReconstructionCandidates(ciphertext.policy, key);
    expect(enumeration.ok).toBe(true);
    if (!enumeration.ok) return;
    expect(enumeration.candidates).toHaveLength(1);
    expect(enumeration.candidates[0].terms).toEqual([
      { rowIndex: 1, coefficient: 2n },
      { rowIndex: 2, coefficient: mod(-1n) },
    ]);

    resetPairingCount();
    const recovered = decryptCandidate(ciphertext, key, enumeration.candidates[0]);
    expect(pairingCount()).toBe(FABESA_PAIRING_TERMS_PER_CANDIDATE);
    expect(gtEquals(recovered, message)).toBe(true);
  });

  it('pins a deterministic cross-operation fingerprint', () => {
    const rng = seededRandom('fabesa:pinned-fingerprint/v1');
    const { pk, msk } = setup(rng);
    const attributes = [
      { name: 'Department', value: 'Cardiology' },
      { name: 'Clearance', value: 'Clinical' },
    ];
    const key = keygen(pk, msk, attributes, rng, 'holder');
    const message = gtPow(pairing(g1, g2), 2024n);
    const ciphertext = encrypt(pk, andPolicy(attributes[0], attributes[1]), message, rng, 'ct');
    const material = [
      g1ToHex(pk.g3),
      g2ToHex(pk.B1),
      g2ToHex(pk.B2),
      gtToHex(pk.EAlpha),
      g2ToHex(key.sk1),
      g1ToHex(key.sk2),
      ...attributes.flatMap((attribute) => {
        const component = key.components.get(attribute.name);
        if (!component) throw new Error('fixture component absent');
        return [g1ToHex(component.sk3), g1ToHex(component.sk4)];
      }),
      ...ciphertext.ct1.map(g1ToHex),
      g2ToHex(ciphertext.ct2),
      g2ToHex(ciphertext.ct3),
      g2ToHex(ciphertext.ct4),
      gtToHex(ciphertext.ct5),
    ].join('|');
    const fingerprint = bytesToHex(sha256(new TextEncoder().encode(material)));
    expect(fingerprint).toBe('840e9021ef475d822e56ebd8c819a6667837a9dabd65457166bf90578059fe86');
  });
});

describe('the partially hidden boundary', () => {
  it('publishes matrix, dimensions, order and names but retains no raw values', () => {
    const rng = seededRandom('fabesa:hidden-boundary');
    const { pk, msk } = setup(rng);
    const hiddenA = 'Cardiology-secret-77';
    const hiddenB = 'Clinical-secret-88';
    const policy = andPolicy(
      { name: 'Department', value: hiddenA },
      { name: 'Clearance', value: hiddenB },
    );
    const key = keygen(
      pk,
      msk,
      [
        { name: 'Department', value: hiddenA },
        { name: 'Clearance', value: hiddenB },
      ],
      rng,
      'holder',
    );
    const ciphertext = encrypt(pk, policy, gtPow(pairing(g1, g2), 7n), rng, 'hidden');

    expect(ciphertext.policy).toEqual({
      columns: 2,
      rows: [
        { index: 1, name: 'Department', vector: [1n, 1n] },
        { index: 2, name: 'Clearance', vector: [1n, 2n] },
      ],
    });
    expect(key.names).toEqual(['Department', 'Clearance']);
    expect([...key.components.keys()]).toEqual(['Department', 'Clearance']);
    expect(Object.keys(key).sort()).toEqual(['components', 'names', 'sk1', 'sk2']);
    expect(Object.keys(ciphertext.policy.rows[0]).sort()).toEqual(['index', 'name', 'vector']);
    expect(containsString(ciphertext, hiddenA)).toBe(false);
    expect(containsString(ciphertext, hiddenB)).toBe(false);
    expect(containsString(key, hiddenA)).toBe(false);
    expect(containsString(key, hiddenB)).toBe(false);
  });

  it('identical names and matrix produce identical public payloads for different values', () => {
    const first = single('Department', 'Cardiology');
    const second = single('Department', 'Oncology');
    expect(publicPolicyOf(first)).toEqual(publicPolicyOf(second));
    expect(g1ToHex(hashHiddenAttribute(0, first.rows[0]))).not.toBe(
      g1ToHex(hashHiddenAttribute(0, second.rows[0])),
    );
  });

  it('AAD binds only canonical public metadata and fixed context', () => {
    const context = 'medical-record/v1';
    const a = encodeEnvelopeAad(publicPolicyOf(single('Department', 'Cardiology')), context);
    const b = encodeEnvelopeAad(publicPolicyOf(single('Department', 'Oncology')), context);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    const readable = new TextDecoder().decode(a);
    expect(readable).toContain('Department');
    expect(readable).not.toContain('Cardiology');
    expect(readable).not.toContain('Oncology');
  });

  it('labels the theorem boundary instead of transferring it to the hybrid wrapper', () => {
    expect(FABESA_SECURITY_SCOPE.theorem).toContain('Theorem 4');
    expect(FABESA_SECURITY_SCOPE.theorem).toContain('DLIN');
    expect(FABESA_SECURITY_SCOPE.adaptation).toContain('not transferred');
  });
});

describe('bounded public-name candidate search with AEAD as the only oracle', () => {
  it('opens a correct one-row envelope without receiving expected plaintext', async () => {
    const rng = seededRandom('fabesa:hybrid-correct');
    const { pk, msk } = setup(rng);
    const policy = single('Department', 'Cardiology');
    const key = keygen(pk, msk, [{ name: 'Department', value: 'Cardiology' }], rng, 'alice');
    const envelope = await sealEnvelope(pk, policy, RECORD, rng, 'lesson/v1', 'record');
    const opened = await openEnvelope(envelope, key);
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.plaintext).toBe(RECORD);
    expect(opened.attempts).toEqual([
      {
        candidate: { terms: [{ rowIndex: 1, coefficient: 1n }] },
        tagAccepted: true,
        pairings: 4,
      },
    ]);
    expect(opened.pairings).toBe(4);
  });

  it('distinguishes four nominal terms from executed identity-short-circuited pairings', async () => {
    const base = seededRandom('fabesa:zero-r');
    const zeroR: RandomSource = {
      kind: 'seeded',
      scalar(label: string): bigint {
        return label.startsWith('fabesa:r') ? 0n : base.scalar(label);
      },
      nonZeroScalar(label: string): bigint {
        return base.nonZeroScalar(label);
      },
      bytes(label: string, length: number): Uint8Array {
        return base.bytes(label, length);
      },
    };
    const { pk, msk } = setup(zeroR);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], zeroR, 'holder');
    const envelope = await sealEnvelope(
      pk,
      single(attribute.name, attribute.value),
      RECORD,
      zeroR,
      '',
      'record',
    );
    const opened = await openEnvelope(envelope, key);
    expect(FABESA_PAIRING_TERMS_PER_CANDIDATE).toBe(4);
    expect(opened.ok).toBe(true);
    expect(opened.pairings).toBe(1);
    expect(opened.attempts[0].pairings).toBe(1);
  });

  it('tries a wrong hidden-value branch before the correct branch', async () => {
    const rng = seededRandom('fabesa:hybrid-search');
    const { pk, msk } = setup(rng);
    const policy = orPolicy([
      { name: 'Department', value: 'Cardiology' },
      { name: 'Role', value: 'Doctor' },
    ]);
    const key = keygen(
      pk,
      msk,
      [
        { name: 'Department', value: 'Oncology' },
        { name: 'Role', value: 'Doctor' },
      ],
      rng,
      'alice',
    );
    const envelope = await sealEnvelope(pk, policy, RECORD, rng, 'lesson/v1', 'record');
    const opened = await openEnvelope(envelope, key);
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.plaintext).toBe(RECORD);
    expect(opened.attempts.map((attempt) => attempt.tagAccepted)).toEqual([false, true]);
    expect(opened.attempts.map((attempt) => attempt.candidate.terms[0].rowIndex)).toEqual([1, 2]);
    expect(opened.pairings).toBe(8);
  });

  it('same public name with the wrong hidden value gives a generic tag rejection', async () => {
    const rng = seededRandom('fabesa:hybrid-wrong-value');
    const { pk, msk } = setup(rng);
    const envelope = await sealEnvelope(
      pk,
      single('Department', 'Cardiology'),
      RECORD,
      rng,
      'lesson/v1',
      'record',
    );
    const wrong = keygen(pk, msk, [{ name: 'Department', value: 'Oncology' }], rng, 'wrong');
    const opened = await openEnvelope(envelope, wrong);
    expect(opened).toMatchObject({
      ok: false,
      reason: 'NO_CANDIDATE_OPENED',
      pairings: 4,
    });
    expect(opened.attempts).toHaveLength(1);
    expect(opened.attempts[0].tagAccepted).toBe(false);
  });

  it('rethrows unexpected WebCrypto failures instead of calling them tag rejection', async () => {
    const rng = seededRandom('fabesa:unexpected-webcrypto');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'holder');
    const envelope = await sealEnvelope(
      pk,
      single(attribute.name, attribute.value),
      RECORD,
      rng,
      'lesson/v1',
      'record',
    );
    const failure = new TypeError('synthetic WebCrypto runtime failure');
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt').mockRejectedValueOnce(failure);
    try {
      await expect(openEnvelope(envelope, key)).rejects.toBe(failure);
    } finally {
      decrypt.mockRestore();
    }
  });

  it('a missing public name yields zero candidates and zero pairings', async () => {
    const rng = seededRandom('fabesa:hybrid-missing-name');
    const { pk, msk } = setup(rng);
    const envelope = await sealEnvelope(
      pk,
      single('Department', 'Cardiology'),
      RECORD,
      rng,
      '',
      'record',
    );
    const key = keygen(pk, msk, [{ name: 'Role', value: 'Doctor' }], rng, 'wrong-name');
    const opened = await openEnvelope(envelope, key);
    expect(opened).toMatchObject({
      ok: false,
      reason: 'NO_PUBLIC_RECONSTRUCTION',
      attempts: [],
      pairings: 0,
    });
  });

  it('fails closed when the matched-row or candidate bound is exceeded', () => {
    const rng = seededRandom('fabesa:bounds');
    const { pk, msk } = setup(rng);
    const attributes = Array.from({ length: DEFAULT_ENUMERATION_LIMITS.maxMatchedRows + 1 }, (_, i) => ({
      name: `Name${i}`,
      value: `Value${i}`,
    }));
    const policy = orPolicy(attributes);
    const key = keygen(pk, msk, attributes, rng, 'many');
    const rowBound = enumerateReconstructionCandidates(publicPolicyOf(policy), key);
    expect(rowBound).toMatchObject({
      ok: false,
      reason: 'MATCHED_ROW_BOUND_EXCEEDED',
      subsetsExamined: 0,
      limit: DEFAULT_ENUMERATION_LIMITS.maxMatchedRows,
    });

    const two = attributes.slice(0, 2);
    const twoPolicy = publicPolicyOf(orPolicy(two));
    const twoKey = keygen(pk, msk, two, rng, 'two');
    const candidateBound = enumerateReconstructionCandidates(twoPolicy, twoKey, {
      maxCandidates: 1,
    });
    expect(candidateBound).toMatchObject({
      ok: false,
      reason: 'CANDIDATE_BOUND_EXCEEDED',
      limit: 1,
    });

    // Every 3-row subset of a 3-of-7 Shamir matrix reconstructs the secret:
    // C(7,3) = 35 minimal candidates, so the hard default cap of 32 must bite
    // on candidate 33 without any caller-supplied lower override.
    const seven = Array.from({ length: 7 }, (_, i) => ({
      name: `Threshold${i + 1}`,
      value: `Value${i + 1}`,
      vector: [1n, BigInt(i + 1), BigInt((i + 1) ** 2)],
    }));
    const sevenKey = keygen(
      pk,
      msk,
      seven.map(({ name, value }) => ({ name, value })),
      rng,
      'seven',
    );
    const defaultCandidateBound = enumerateReconstructionCandidates(
      publicPolicyOf({ rows: seven }),
      sevenKey,
    );
    expect(defaultCandidateBound).toMatchObject({
      ok: false,
      reason: 'CANDIDATE_BOUND_EXCEEDED',
      limit: 32,
    });
  });
});

describe('negative cryptographic cases', () => {
  it('an exact-value key from a different authority fails authentication', async () => {
    const rngA = seededRandom('fabesa:authority-a');
    const rngB = seededRandom('fabesa:authority-b');
    const a = setup(rngA);
    const b = setup(rngB);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const envelope = await sealEnvelope(a.pk, single(attribute.name, attribute.value), RECORD, rngA);
    const foreign = keygen(b.pk, b.msk, [attribute], rngB, 'foreign');
    const opened = await openEnvelope(envelope, foreign);
    expect(opened).toMatchObject({ ok: false, reason: 'NO_CANDIDATE_OPENED', pairings: 4 });
  });

  it('splicing components from another randomized key does not authenticate', async () => {
    const rng = seededRandom('fabesa:spliced-r');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const first = keygen(pk, msk, [attribute], rng, 'first');
    const second = keygen(pk, msk, [attribute], rng, 'second');
    const borrowed = second.components.get(attribute.name);
    if (!borrowed) throw new Error('test key missing component');
    const spliced: SecretKey = {
      ...first,
      components: new Map([[attribute.name, borrowed]]),
    };
    const envelope = await sealEnvelope(pk, single(attribute.name, attribute.value), RECORD, rng);
    const opened = await openEnvelope(envelope, spliced);
    expect(opened).toMatchObject({ ok: false, reason: 'NO_CANDIDATE_OPENED', pairings: 4 });
  });

  it('tampering with ciphertext, public policy AAD, or context is rejected', async () => {
    const rng = seededRandom('fabesa:tamper');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'alice');
    const envelope = await sealEnvelope(
      pk,
      single(attribute.name, attribute.value),
      RECORD,
      rng,
      'record/v1',
      'record',
    );

    const sealed = Uint8Array.from(envelope.sealed);
    sealed[0] ^= 1;
    expect(await openEnvelope({ ...envelope, sealed }, key)).toMatchObject({
      ok: false,
      reason: 'NO_CANDIDATE_OPENED',
    });

    const policyChanged = {
      ...envelope,
      abe: {
        ...envelope.abe,
        policy: {
          ...envelope.abe.policy,
          rows: [{ ...envelope.abe.policy.rows[0], vector: [2n] }],
        },
      },
    };
    expect(await openEnvelope(policyChanged, key)).toMatchObject({
      ok: false,
      reason: 'NO_CANDIDATE_OPENED',
    });
    expect(await openEnvelope({ ...envelope, context: 'record/v2' }, key)).toMatchObject({
      ok: false,
      reason: 'NO_CANDIDATE_OPENED',
    });
  });

  it('rejects a malformed ct1 row count before candidate work', async () => {
    const rng = seededRandom('fabesa:malformed-ciphertext');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'alice');
    const envelope = await sealEnvelope(pk, single(attribute.name, attribute.value), RECORD, rng);
    const malformed = {
      ...envelope,
      abe: { ...envelope.abe, ct1: [] },
    };
    await expect(openEnvelope(malformed, key)).rejects.toMatchObject({
      name: 'FabesaCiphertextError',
      code: 'MALFORMED_CIPHERTEXT',
    });
    const extra = {
      ...envelope,
      abe: { ...envelope.abe, ct1: [...envelope.abe.ct1, envelope.abe.ct1[0]] },
    };
    await expect(openEnvelope(extra, key)).rejects.toMatchObject({
      name: 'FabesaCiphertextError',
      code: 'MALFORMED_CIPHERTEXT',
    });
  });

  it('rejects inconsistent key names and components before enumeration', () => {
    const rng = seededRandom('fabesa:malformed-key');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'alice');
    const malformed: SecretKey = { ...key, names: ['Department', 'Role'] };
    expect(() =>
      enumerateReconstructionCandidates(publicPolicyOf(single(attribute.name, attribute.value)), malformed),
    ).toThrowError(/MALFORMED_SECRET_KEY.*Role.*absent/);
  });

  it('rejects malformed profile inputs and externally supplied bad coefficients', () => {
    const rng = seededRandom('fabesa:malformed');
    const { pk, msk } = setup(rng);
    expect(() =>
      keygen(
        pk,
        msk,
        [
          { name: 'Department', value: 'Cardiology' },
          { name: 'Department', value: 'Oncology' },
        ],
        rng,
      ),
    ).toThrowError(/multi-use extension/);
    expect(() =>
      publicPolicyOf({
        rows: [
          { name: 'A', value: '1', vector: [1n] },
          { name: 'B', value: '2', vector: [1n, 2n] },
        ],
      }),
    ).toThrowError(/expected 1/);

    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'good');
    const message = gtPow(pairing(g1, g2), 5n);
    const ciphertext = encrypt(pk, single(attribute.name, attribute.value), message, rng, 'good');
    expect(() =>
      decryptCandidate(ciphertext, key, {
        terms: [{ rowIndex: 1, coefficient: 2n }],
      }),
    ).toThrowError(/do not reconstruct/);
    expect(() =>
      enumerateReconstructionCandidates(ciphertext.policy, key, {
        maxCandidates: DEFAULT_ENUMERATION_LIMITS.maxCandidates + 1,
      }),
    ).toThrowError(/FABESA_LIMIT/);
  });

  it('a valid candidate is derived from public data rather than an expected message', () => {
    const rng = seededRandom('fabesa:no-plaintext-shortcut');
    const { pk, msk } = setup(rng);
    const attribute = { name: 'Department', value: 'Cardiology' };
    const key = keygen(pk, msk, [attribute], rng, 'holder');
    const message = gtPow(pairing(g1, g2), 99n);
    const ciphertext = encrypt(pk, single(attribute.name, attribute.value), message, rng, 'record');
    const candidate = onlyCandidate(ciphertext.policy, key);
    expect(gtEquals(decryptCandidate(ciphertext, key, candidate), message)).toBe(true);
    // The API takes exactly ciphertext, key and public reconstruction; no
    // expected message/plaintext parameter exists (unlike the author artifact).
    expect(decryptCandidate.length).toBe(3);
  });
});
