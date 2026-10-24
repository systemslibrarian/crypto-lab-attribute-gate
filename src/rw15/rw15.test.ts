import { describe, expect, test, vi } from 'vitest';
import {
  ORDER,
  g1,
  g1Mul,
  g1Pow,
  g1ToHex,
  g2,
  g2Mul,
  g2Pow,
  g2ToHex,
  gtEquals,
  gtMul,
  gtPow,
  gtToHex,
  pairing,
  resetPairingCount,
} from '../fame/bls';
import { seededRandom } from '../fame/rand';
import {
  RW15_ATTRIBUTE_DST,
  RW15_EGG,
  RW15_GID_DST,
  canonicalAuthorityId,
  canonicalGid,
  compileRwPolicy,
  formatRwPolicy,
  parseQualifiedAttribute,
  reconstructRw,
  resetRwPolicyIds,
  rwAnd,
  rwAttr,
  rwAuthoritySetup,
  rwDecrypt,
  rwEncrypt,
  rwHashAttribute,
  rwHashGid,
  rwKeygen,
  rwOpenRecord,
  rwOr,
  rwRandomGT,
  rwRawDecrypt,
  rwRowTerm,
  rwSealRecord,
  rwThreshold,
  type RwAttributeKey,
  type RwAuthority,
  type RwCiphertext,
  type RwLsss,
  type RwSealedRecord,
} from './index';

const mod = (value: bigint): bigint => {
  const reduced = value % ORDER;
  return reduced < 0n ? reduced + ORDER : reduced;
};

const independentDot = (a: readonly bigint[], b: readonly bigint[]): bigint =>
  mod(a.reduce((sum, value, index) => sum + value * b[index], 0n));

const expectG1 = (actual: Parameters<typeof g1ToHex>[0], expected: Parameters<typeof g1ToHex>[0]) =>
  expect(g1ToHex(actual)).toBe(g1ToHex(expected));

const expectG2 = (actual: Parameters<typeof g2ToHex>[0], expected: Parameters<typeof g2ToHex>[0]) =>
  expect(g2ToHex(actual)).toBe(g2ToHex(expected));

const expectGT = (actual: Parameters<typeof gtToHex>[0], expected: Parameters<typeof gtToHex>[0]) =>
  expect(gtToHex(actual)).toBe(gtToHex(expected));

interface Fixture {
  hospital: RwAuthority;
  board: RwAuthority;
  lsss: RwLsss;
  aliceDoctor: RwAttributeKey;
  aliceCardiology: RwAttributeKey;
  ciphertext: RwCiphertext;
  message: ReturnType<typeof rwRandomGT>['element'];
  witnesses: ReturnType<typeof rwEncrypt>['witness'];
  doctorT: bigint;
  cardiologyT: bigint;
}

const MALFORMED_RECORDS: ReadonlyArray<
  readonly [string, (record: RwSealedRecord) => RwSealedRecord]
> = [
  ['empty nonce', (record) => ({ ...record, nonce: new Uint8Array() })],
  ['11-byte nonce', (record) => ({ ...record, nonce: new Uint8Array(11) })],
  ['13-byte nonce', (record) => ({ ...record, nonce: new Uint8Array(13) })],
  ['empty ciphertext', (record) => ({ ...record, ciphertext: new Uint8Array() })],
  ['ciphertext shorter than the tag', (record) => ({ ...record, ciphertext: new Uint8Array(15) })],
  ['non-string AAD', (record) => ({ ...record, aad: 7 as unknown as string })],
];

function fixture(seed = 'rw15-fixture'): Fixture {
  resetRwPolicyIds();
  const rng = seededRandom(seed);
  const hospital = rwAuthoritySetup('Hospital', rng);
  const board = rwAuthoritySetup('Board', rng);
  const lsss = compileRwPolicy(
    rwAnd(
      [rwAttr('Doctor@Hospital', 'doctor'), rwAttr('Cardiology@Board', 'cardiology')],
      'root',
    ),
  );
  const doctor = rwKeygen(hospital.sk, 'gid:alice', 'Doctor@Hospital', rng);
  const cardiology = rwKeygen(board.sk, 'gid:alice', 'Cardiology@Board', rng);
  const message = rwRandomGT(rng, 'fixture').element;
  const encrypted = rwEncrypt(
    new Map([
      [hospital.pk.id, hospital.pk],
      [board.pk.id, board.pk],
    ]),
    lsss,
    message,
    rng,
  );
  return {
    hospital,
    board,
    lsss,
    aliceDoctor: doctor.key,
    aliceCardiology: cardiology.key,
    ciphertext: encrypted.ciphertext,
    message,
    witnesses: encrypted.witness,
    doctorT: doctor.witness.t,
    cardiologyT: cardiology.witness.t,
  };
}

describe('RW15 canonical identifiers and independent random oracles', () => {
  test('accepts only exact, case-sensitive ASCII attribute@authority names', () => {
    expect(parseQualifiedAttribute('Doctor@Hospital')).toEqual({
      attribute: 'Doctor',
      authority: 'Hospital',
      qualified: 'Doctor@Hospital',
    });
    expect(canonicalAuthorityId('Hospital-2')).toBe('Hospital-2');
    expect(canonicalGid('gid:Alice+2026')).toBe('gid:Alice+2026');

    for (const malformed of [
      'Doctor',
      '@Hospital',
      'Doctor@',
      'Doctor@Hospital@Other',
      'Doctor Name@Hospital',
      'Dóctor@Hospital',
    ]) {
      expect(() => parseQualifiedAttribute(malformed), malformed).toThrow(/RW15_/);
    }
    for (const malformed of ['', 'gid alice', 'gíd:alice', '@alice']) {
      expect(() => canonicalGid(malformed), malformed).toThrow(/RW15_GID/);
    }
  });

  test('does not silently case-fold GIDs or attributes', () => {
    expect(g2ToHex(rwHashGid('gid:Alice'))).not.toBe(g2ToHex(rwHashGid('gid:alice')));
    expect(g2ToHex(rwHashAttribute('Doctor@Hospital'))).not.toBe(
      g2ToHex(rwHashAttribute('doctor@Hospital')),
    );
  });

  test('H and F use distinct G2 domain-separation tags', () => {
    expect(RW15_GID_DST).not.toBe(RW15_ATTRIBUTE_DST);
    expect(RW15_GID_DST).toContain('BLS12381G2_XMD:SHA-256_SSWU_RO_');
    expect(RW15_ATTRIBUTE_DST).toContain('BLS12381G2_XMD:SHA-256_SSWU_RO_');
    expect(rwHashGid('Doctor').is0()).toBe(false);
    expect(rwHashAttribute('Doctor@Hospital').is0()).toBe(false);
  });
});

describe('RW15 LSSS compiler', () => {
  test('compiles threshold rows and independently verifies reconstruction', () => {
    resetRwPolicyIds();
    const lsss = compileRwPolicy(
      rwThreshold(
        2,
        [
          rwAttr('A@One', 'a'),
          rwAttr('B@Two', 'b'),
          rwAttr('C@Three', 'c'),
        ],
        'root',
      ),
    );
    expect(lsss.columns).toBe(2);
    expect(lsss.rows.map((row) => row.vector)).toEqual([
      [1n, 1n],
      [1n, 2n],
      [1n, 3n],
    ]);
    const reconstruction = reconstructRw(lsss, new Set(['A@One', 'C@Three']));
    expect(reconstruction.satisfied).toBe(true);

    const combined = Array<bigint>(lsss.columns).fill(0n);
    for (const rowIndex of reconstruction.usedRows) {
      const coefficient = reconstruction.coefficients.get(rowIndex) as bigint;
      const row = lsss.rows[rowIndex - 1];
      row.vector.forEach((value, column) => {
        combined[column] = mod(combined[column] + coefficient * value);
      });
    }
    expect(combined).toEqual([1n, 0n]);
  });

  test('permits a repeated logical attribute without occurrence suffixes', () => {
    resetRwPolicyIds();
    const policy = rwAnd(
      [
        rwOr([rwAttr('STUDENT@UT', 's1'), rwAttr('PROFESSOR@OU', 'p')], 'left'),
        rwOr([rwAttr('STUDENT@UT', 's2'), rwAttr('MASTERS@OU', 'm')], 'right'),
      ],
      'root',
    );
    const lsss = compileRwPolicy(policy);
    expect(lsss.rows.map((row) => row.attribute)).toEqual([
      'STUDENT@UT',
      'PROFESSOR@OU',
      'STUDENT@UT',
      'MASTERS@OU',
    ]);
    expect(lsss.rows.some((row) => row.attribute.includes(':1'))).toBe(false);
    const reconstruction = reconstructRw(lsss, new Set(['STUDENT@UT']));
    expect(reconstruction.satisfied).toBe(true);
    expect(reconstruction.usedRows).toEqual([1, 3]);
    expect(formatRwPolicy(policy)).toBe(
      '((STUDENT@UT OR PROFESSOR@OU) AND (STUDENT@UT OR MASTERS@OU))',
    );
  });

  test('rejects malformed gates, duplicate ids, and unqualified attributes', () => {
    expect(() => compileRwPolicy(rwThreshold(0, [rwAttr('A@One')]))).toThrow(/threshold/);
    expect(() =>
      compileRwPolicy(
        rwAnd([rwAttr('A@One', 'same'), rwAttr('B@Two', 'same')], 'root'),
      ),
    ).toThrow(/duplicate node id/);
    expect(() => rwAttr('Unqualified')).toThrow(/attribute@authority/);
  });
});

describe('RW15 exact Type-3 equations', () => {
  test('independently reconstructs both authority public keys', () => {
    const f = fixture();
    for (const authority of [f.hospital, f.board]) {
      expectGT(authority.pk.egga, gtPow(RW15_EGG, authority.sk.alpha));
      expectG1(authority.pk.gy, g1Pow(g1, authority.sk.y));
    }
  });

  test('independently reconstructs both attribute-key components', () => {
    const f = fixture();
    for (const [authority, key, t] of [
      [f.hospital, f.aliceDoctor, f.doctorT],
      [f.board, f.aliceCardiology, f.cardiologyT],
    ] as const) {
      const expectedK = g2Mul(
        g2Mul(
          g2Pow(g2, authority.sk.alpha),
          g2Pow(rwHashGid(key.gid), authority.sk.y),
        ),
        g2Pow(rwHashAttribute(key.attribute), t),
      );
      expectG2(key.K, expectedK);
      expectG1(key.KPrime, g1Pow(g1, t));
    }
  });

  test('independently recomputes v, w, every share, and C1-C4', () => {
    const f = fixture();
    expect(f.witnesses.w[0]).toBe(0n);
    expect(f.witnesses.v[0]).toBe(f.witnesses.z);
    const authorities = new Map([
      [f.hospital.pk.id, f.hospital],
      [f.board.pk.id, f.board],
    ]);
    for (const row of f.lsss.rows) {
      const witness = f.witnesses.rows.get(row.index);
      expect(witness).toBeDefined();
      const lambda = independentDot(row.vector, f.witnesses.v);
      const omega = independentDot(row.vector, f.witnesses.w);
      expect(witness?.lambda).toBe(lambda);
      expect(witness?.omega).toBe(omega);
      const authority = authorities.get(row.authority) as RwAuthority;
      const actual = f.ciphertext.rows[row.index - 1];
      expectGT(actual.C1, gtMul(gtPow(RW15_EGG, lambda), gtPow(authority.pk.egga, witness?.tx ?? 0n)));
      expectG1(actual.C2, g1Pow(g1, mod(-(witness?.tx ?? 0n))));
      expectG1(
        actual.C3,
        g1Mul(g1Pow(authority.pk.gy, witness?.tx ?? 0n), g1Pow(g1, omega)),
      );
      expectG2(actual.C4, g2Pow(rwHashAttribute(row.attribute), witness?.tx ?? 0n));
    }
    expectGT(
      f.ciphertext.C0,
      gtMul(f.message, gtPow(RW15_EGG, f.witnesses.z)),
    );
  });

  test('checks the paper row identity and zero-share cancellation independently', () => {
    const f = fixture();
    const keys = [f.aliceDoctor, f.aliceCardiology];
    const keyByAttribute = new Map(keys.map((key) => [key.attribute, key]));
    const reconstruction = reconstructRw(f.lsss, new Set(keyByAttribute.keys()));
    let lambdaSum = 0n;
    let omegaSum = 0n;
    for (const rowIndex of reconstruction.usedRows) {
      const row = f.lsss.rows[rowIndex - 1];
      const ctRow = f.ciphertext.rows[rowIndex - 1];
      const key = keyByAttribute.get(row.attribute) as RwAttributeKey;
      const witness = f.witnesses.rows.get(rowIndex);
      const coefficient = reconstruction.coefficients.get(rowIndex) as bigint;
      const independentlyCombined = gtMul(
        gtMul(ctRow.C1, pairing(ctRow.C2, key.K)),
        gtMul(
          pairing(ctRow.C3, rwHashGid('gid:alice')),
          pairing(key.KPrime, ctRow.C4),
        ),
      );
      const expected = gtMul(
        gtPow(RW15_EGG, witness?.lambda ?? 0n),
        gtPow(pairing(g1, rwHashGid('gid:alice')), witness?.omega ?? 0n),
      );
      expectGT(independentlyCombined, expected);
      lambdaSum = mod(lambdaSum + coefficient * (witness?.lambda ?? 0n));
      omegaSum = mod(omegaSum + coefficient * (witness?.omega ?? 0n));
    }
    expect(lambdaSum).toBe(f.witnesses.z);
    expect(omegaSum).toBe(0n);
  });
});

describe('RW15 same-user composition and repeated attributes', () => {
  test('combines keys from two independent authorities only for the same GID', () => {
    const f = fixture();
    resetPairingCount();
    const result = rwDecrypt(f.ciphertext, 'gid:alice', [
      f.aliceDoctor,
      f.aliceCardiology,
    ]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expectGT(result.recovered, f.message);
    expect(result.pairings).toBe(6);
  });

  test('one STUDENT@UT key opens both repeated rows in the authors policy shape', () => {
    resetRwPolicyIds();
    const rng = seededRandom('rw15-repeated');
    const ut = rwAuthoritySetup('UT', rng);
    const ou = rwAuthoritySetup('OU', rng);
    const lsss = compileRwPolicy(
      rwAnd([
        rwOr([rwAttr('STUDENT@UT'), rwAttr('PROFESSOR@OU')]),
        rwOr([rwAttr('STUDENT@UT'), rwAttr('MASTERS@OU')]),
      ]),
    );
    const student = rwKeygen(ut.sk, 'bob', 'STUDENT@UT', rng).key;
    const message = rwRandomGT(rng, 'repeated').element;
    const { ciphertext } = rwEncrypt(
      new Map([
        ['UT', ut.pk],
        ['OU', ou.pk],
      ]),
      lsss,
      message,
      rng,
    );
    const result = rwDecrypt(ciphertext, 'bob', [student]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.reconstruction.usedRows).toEqual([1, 3]);
      expectGT(result.recovered, message);
    }
  });

  test('a byte-different GID is not treated as the same user', () => {
    const f = fixture();
    const result = rwDecrypt(f.ciphertext, 'gid:Alice', [
      f.aliceDoctor,
      f.aliceCardiology,
    ]);
    expect(result).toMatchObject({ ok: false, code: 'POLICY_UNSATISFIED', pairings: 0 });
  });
});

describe('RW15 cryptographic GID binding', () => {
  test('blocks the strongest raw cross-GID pooling attempt, not merely a metadata mismatch', async () => {
    resetRwPolicyIds();
    const rng = seededRandom('rw15-cross-gid');
    const hospital = rwAuthoritySetup('Hospital', rng);
    const board = rwAuthoritySetup('Board', rng);
    const lsss = compileRwPolicy(
      rwAnd([rwAttr('Doctor@Hospital'), rwAttr('Cardiology@Board')]),
    );
    const bob = rwKeygen(hospital.sk, 'gid:bob', 'Doctor@Hospital', rng).key;
    const eve = rwKeygen(board.sk, 'gid:eve', 'Cardiology@Board', rng).key;
    const message = rwRandomGT(rng, 'cross-gid').element;
    const { ciphertext } = rwEncrypt(
      new Map([
        ['Hospital', hospital.pk],
        ['Board', board.pk],
      ]),
      lsss,
      message,
      rng,
    );

    expect(rwDecrypt(ciphertext, 'gid:bob', [bob])).toMatchObject({ ok: false });
    expect(rwDecrypt(ciphertext, 'gid:eve', [eve])).toMatchObject({ ok: false });

    // The adversary uses each borrowed component's own public H(GID), which
    // cancels every y*t_x term row-by-row. Only the zero-share/GID binding is
    // left to stop the union.
    const pooled = rwRawDecrypt(ciphertext, [
      { rowIndex: 1, key: bob, pairingGid: bob.gid },
      { rowIndex: 2, key: eve, pairingGid: eve.gid },
    ]);
    expect(pooled.ok).toBe(true);
    if (!pooled.ok) return;
    expect(gtEquals(pooled.recovered, message)).toBe(false);

    const sealed = await rwSealRecord(message, 'oncology record', formatRwPolicy(lsss.policy), rng);
    await expect(rwOpenRecord(pooled.recovered, sealed)).resolves.toEqual({
      ok: false,
      code: 'AEAD_TAG_REJECTED',
    });
  });

  test('the same raw formula succeeds when all row keys have one GID', () => {
    const f = fixture('rw15-raw-same-gid');
    const result = rwRawDecrypt(f.ciphertext, [
      { rowIndex: 1, key: f.aliceDoctor, pairingGid: f.aliceDoctor.gid },
      { rowIndex: 2, key: f.aliceCardiology, pairingGid: f.aliceCardiology.gid },
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) expectGT(result.recovered, f.message);
  });
});

describe('RW15 authority compromise boundary', () => {
  test('one compromised issuer can mint every one of its attributes, but not an honest AND branch', () => {
    const f = fixture('rw15-compromise-and');
    const rng = seededRandom('rw15-compromise-key');
    // Possession of Hospital's alpha,y is exactly what compromise grants.
    const forgedHospital = rwKeygen(
      f.hospital.sk,
      'gid:mallory',
      'Doctor@Hospital',
      rng,
    ).key;
    const result = rwDecrypt(f.ciphertext, 'gid:mallory', [forgedHospital]);
    expect(result).toMatchObject({ ok: false, code: 'POLICY_UNSATISFIED' });
  });

  test('a compromised issuer completely breaks a policy branch it can satisfy alone', () => {
    resetRwPolicyIds();
    const rng = seededRandom('rw15-compromise-or');
    const hospital = rwAuthoritySetup('Hospital', rng);
    const board = rwAuthoritySetup('Board', rng);
    const lsss = compileRwPolicy(
      rwOr([rwAttr('Doctor@Hospital'), rwAttr('Cardiology@Board')]),
    );
    const forged = rwKeygen(hospital.sk, 'gid:mallory', 'Doctor@Hospital', rng).key;
    const message = rwRandomGT(rng, 'compromise-or').element;
    const { ciphertext } = rwEncrypt(
      new Map([
        ['Hospital', hospital.pk],
        ['Board', board.pk],
      ]),
      lsss,
      message,
      rng,
    );
    const result = rwDecrypt(ciphertext, 'gid:mallory', [forged]);
    expect(result.ok).toBe(true);
    if (result.ok) expectGT(result.recovered, message);
  });
});

describe('RW15 fail-closed boundaries and tampering', () => {
  test('refuses issuance by the wrong authority', () => {
    const rng = seededRandom('rw15-wrong-authority');
    const hospital = rwAuthoritySetup('Hospital', rng);
    expect(() =>
      rwKeygen(hospital.sk, 'gid:alice', 'Cardiology@Board', rng),
    ).toThrow(/RW15_AUTHORITY_MISMATCH/);
  });

  test('refuses a missing or mislabeled authority public key', () => {
    const f = fixture('rw15-pk-errors');
    const rng = seededRandom('rw15-pk-errors-encrypt');
    expect(() => rwEncrypt(new Map([['Hospital', f.hospital.pk]]), f.lsss, f.message, rng)).toThrow(
      /RW15_PUBLIC_KEY_MISSING: Board/,
    );
    expect(() =>
      rwEncrypt(
        new Map([
          ['Hospital', f.hospital.pk],
          ['Board', { ...f.board.pk, id: 'Other' }],
        ]),
        f.lsss,
        f.message,
        rng,
      ),
    ).toThrow(/RW15_PUBLIC_KEY_MISMATCH/);
  });

  test('refuses a row paired with a key for another attribute', () => {
    const f = fixture('rw15-wrong-row-key');
    expect(() =>
      rwRowTerm(f.ciphertext.rows[0], f.aliceCardiology, 'gid:alice'),
    ).toThrow(/RW15_KEY_ATTRIBUTE_MISMATCH/);
  });

  test.each(['C0', 'C1', 'C2', 'C3', 'C4'] as const)(
    'tampering with %s changes the recovered GT element',
    (component) => {
      const f = fixture(`rw15-tamper-${component}`);
      let tampered: RwCiphertext;
      if (component === 'C0') {
        tampered = { ...f.ciphertext, C0: gtMul(f.ciphertext.C0, RW15_EGG) };
      } else {
        const rows = f.ciphertext.rows.map((row, index) => {
          if (index !== 0) return row;
          if (component === 'C1') return { ...row, C1: gtMul(row.C1, RW15_EGG) };
          if (component === 'C2') return { ...row, C2: g1Mul(row.C2, g1) };
          if (component === 'C3') return { ...row, C3: g1Mul(row.C3, g1) };
          return { ...row, C4: g2Mul(row.C4, g2) };
        });
        tampered = { ...f.ciphertext, rows };
      }
      const result = rwDecrypt(tampered, 'gid:alice', [f.aliceDoctor, f.aliceCardiology]);
      expect(result.ok).toBe(true);
      if (result.ok) expect(gtEquals(result.recovered, f.message)).toBe(false);
    },
  );

  test('fresh key and ciphertext randomness changes components', () => {
    const rng = seededRandom('rw15-freshness');
    const authority = rwAuthoritySetup('Hospital', rng);
    const first = rwKeygen(authority.sk, 'gid:alice', 'Doctor@Hospital', rng, 'one');
    const second = rwKeygen(authority.sk, 'gid:alice', 'Doctor@Hospital', rng, 'two');
    expect(first.witness.t).not.toBe(second.witness.t);
    expect(g2ToHex(first.key.K)).not.toBe(g2ToHex(second.key.K));
    expect(g1ToHex(first.key.KPrime)).not.toBe(g1ToHex(second.key.KPrime));

    resetRwPolicyIds();
    const lsss = compileRwPolicy(
      rwAnd([rwAttr('Doctor@Hospital'), rwAttr('Nurse@Hospital')]),
    );
    const message = rwRandomGT(rng, 'freshness').element;
    const { witness } = rwEncrypt(
      new Map([['Hospital', authority.pk]]),
      lsss,
      message,
      rng,
    );
    expect(witness.rows.get(1)?.tx).not.toBe(witness.rows.get(2)?.tx);
  });
});

describe('RW15-specific KEM/KDF/AEAD boundary', () => {
  test('opens only under the recovered encapsulated element and authenticates AAD', async () => {
    const f = fixture('rw15-kem');
    const rng = seededRandom('rw15-kem-seal');
    const aad = `${formatRwPolicy(f.lsss.policy)}|Hospital|Board`;
    const sealed = await rwSealRecord(f.message, 'bounded teaching record', aad, rng);
    const decrypted = rwDecrypt(f.ciphertext, 'gid:alice', [
      f.aliceDoctor,
      f.aliceCardiology,
    ]);
    expect(decrypted.ok).toBe(true);
    if (!decrypted.ok) return;
    await expect(rwOpenRecord(decrypted.recovered, sealed)).resolves.toEqual({
      ok: true,
      plaintext: 'bounded teaching record',
    });

    const other = rwRandomGT(seededRandom('rw15-kem-wrong'), 'wrong').element;
    await expect(rwOpenRecord(other, sealed)).resolves.toEqual({
      ok: false,
      code: 'AEAD_TAG_REJECTED',
    });
    await expect(rwOpenRecord(decrypted.recovered, { ...sealed, aad: `${aad}|tampered` })).resolves.toEqual({
      ok: false,
      code: 'AEAD_TAG_REJECTED',
    });
  });

  test.each(MALFORMED_RECORDS)('%s is rejected before WebCrypto decrypt', async (_label, mutate) => {
    const shared = rwRandomGT(seededRandom(`rw15-malformed-${_label}`), 'shared').element;
    const sealed = await rwSealRecord(
      shared,
      'bounded teaching record',
      'Doctor@Hospital',
      seededRandom(`rw15-malformed-seal-${_label}`),
    );
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      await expect(rwOpenRecord(shared, mutate(sealed))).resolves.toEqual({
        ok: false,
        code: 'MALFORMED_RECORD',
      });
      expect(decrypt).not.toHaveBeenCalled();
    } finally {
      decrypt.mockRestore();
    }
  });

  test('a same-length ciphertext bit flip reaches WebCrypto and is a tag failure', async () => {
    const shared = rwRandomGT(seededRandom('rw15-tag-shared'), 'shared').element;
    const sealed = await rwSealRecord(
      shared,
      'bounded teaching record',
      'Doctor@Hospital',
      seededRandom('rw15-tag-seal'),
    );
    const ciphertext = new Uint8Array(sealed.ciphertext);
    ciphertext[0] ^= 1;
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      await expect(rwOpenRecord(shared, { ...sealed, ciphertext })).resolves.toEqual({
        ok: false,
        code: 'AEAD_TAG_REJECTED',
      });
      expect(decrypt).toHaveBeenCalledTimes(1);
    } finally {
      decrypt.mockRestore();
    }
  });

  test('rethrows unexpected WebCrypto failures instead of reporting tag rejection', async () => {
    const shared = rwRandomGT(seededRandom('rw15-webcrypto-shared'), 'shared').element;
    const sealed = await rwSealRecord(
      shared,
      'bounded teaching record',
      'Doctor@Hospital',
      seededRandom('rw15-webcrypto-seal'),
    );
    const failure = new TypeError('synthetic WebCrypto runtime failure');
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt').mockRejectedValueOnce(failure);
    try {
      await expect(rwOpenRecord(shared, sealed)).rejects.toBe(failure);
    } finally {
      decrypt.mockRestore();
    }
  });
});
