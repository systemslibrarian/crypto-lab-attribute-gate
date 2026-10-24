import { beforeAll, describe, expect, it, vi } from 'vitest';
import { poolKeys } from '../fame/collusion';
import { attr } from '../fame/policy';
import { seededRandom } from '../fame/rand';
import {
  advanceEpoch,
  authorityEscrowOpen,
  computeAccessHeaderDigest,
  costSnapshot,
  createEpochSystem,
  createOwnerCapability,
  encodeAccessHeader,
  encodePayloadCiphertext,
  issueCurrentEpochKey,
  openEpochRecord,
  ownerOpenRecord,
  rewrapEpochRecord,
  revokeHolder,
  sealEpochRecord,
  takeStorageSnapshot,
  type EpochKeyRecord,
  type EpochSystem,
  type IssueResult,
  type OwnerCapability,
  type RevocableRecord,
  type StoredSnapshot,
} from './epoch';

const bytes = (value: Uint8Array): number[] => Array.from(value);

function issued(result: IssueResult): EpochKeyRecord {
  if (!result.ok) throw new Error(`expected issued key, got ${result.code}`);
  return result.key;
}

function flipped(value: Uint8Array): Uint8Array {
  const copy = new Uint8Array(value);
  copy[0] ^= 0x80;
  return copy;
}

describe('bounded epoch gating and owner-assisted DEK rewrap', () => {
  let system: EpochSystem;
  let owner: OwnerCapability;
  let wrongOwner: OwnerCapability;
  let oldRecord: RevocableRecord;
  let newRecord: RevocableRecord;
  let rewrappedRecord: RevocableRecord;
  let oldSnapshot: StoredSnapshot;
  let newSnapshot: StoredSnapshot;
  let rewrappedSnapshot: StoredSnapshot;
  let aliceEpoch1: EpochKeyRecord;
  let bobEpoch1: EpochKeyRecord;
  let aliceEpoch2: EpochKeyRecord;
  let carolEpoch2: EpochKeyRecord;
  let bobEpoch2Result: IssueResult;

  beforeAll(async () => {
    system = createEpochSystem(seededRandom('revocation-system'));
    owner = await createOwnerCapability('Records owner', seededRandom('revocation-owner'));
    wrongOwner = await createOwnerCapability('Wrong owner', seededRandom('wrong-owner'));
    const doctorPolicy = attr('Doctor', 'doctor-business-rule');

    // Register the epoch-1 policy before issuing complete epoch-1 keys.
    oldRecord = await sealEpochRecord(
      system,
      owner,
      'record-old',
      doctorPolicy,
      'record created in epoch one',
    );
    oldSnapshot = takeStorageSnapshot(oldRecord);
    aliceEpoch1 = issued(
      issueCurrentEpochKey(system, { id: 'Alice', attributes: ['Doctor'] }),
    );
    bobEpoch1 = issued(
      issueCurrentEpochKey(system, { id: 'Bob', attributes: ['Doctor'] }),
    );

    revokeHolder(system, 'Bob');
    advanceEpoch(system);

    // A new epoch-2 header registers its label before current keys are made.
    newRecord = await sealEpochRecord(
      system,
      owner,
      'record-new',
      doctorPolicy,
      'record created after Bob was revoked',
    );
    newSnapshot = takeStorageSnapshot(newRecord);
    aliceEpoch2 = issued(
      issueCurrentEpochKey(system, { id: 'Alice', attributes: ['Doctor'] }),
    );
    bobEpoch2Result = issueCurrentEpochKey(system, {
      id: 'Bob',
      attributes: ['Doctor'],
    });
    carolEpoch2 = issued(
      issueCurrentEpochKey(system, { id: 'Carol', attributes: ['Nurse'] }),
    );

    const rewrap = await rewrapEpochRecord(system, owner, oldRecord);
    if (!rewrap.ok) throw new Error(`fixture rewrap failed: ${rewrap.code}`);
    rewrappedRecord = rewrap.record;
    rewrappedSnapshot = takeStorageSnapshot(rewrappedRecord);
  });

  it('opens current-epoch new data for an active holder', async () => {
    const opened = await openEpochRecord(newSnapshot, aliceEpoch2, newRecord.checkpoint);
    expect(opened).toMatchObject({
      ok: true,
      code: 'OPENED',
      plaintext: 'record created after Bob was revoked',
      epoch: 2,
      revision: 1,
    });
  });

  it('withholds a complete new key and rejects the revoked holder on new data', async () => {
    expect(bobEpoch2Result).toEqual({
      ok: false,
      code: 'HOLDER_REVOKED',
      detail: 'Bob is on the revocation list and receives no epoch 2 key',
    });

    const opened = await openEpochRecord(newSnapshot, bobEpoch1, newRecord.checkpoint);
    expect(opened.ok).toBe(false);
    if (!opened.ok) {
      expect(opened.code).toBe('POLICY_UNSATISFIED');
      expect(opened.detail).toContain('Access epoch 2:1');
    }
  });

  it('reissues the full randomized FAME key rather than an epoch-only component', () => {
    expect(aliceEpoch1.issued.key.labels).toEqual(['Doctor:1', 'Access epoch 1:1']);
    expect(aliceEpoch2.issued.key.labels).toEqual(['Doctor:1', 'Access epoch 2:1']);
    expect(aliceEpoch1.elements).toBe(12);
    expect(aliceEpoch2.elements).toBe(12);
    expect(aliceEpoch1.issued.key.sk0[0].toHex(true)).not.toBe(
      aliceEpoch2.issued.key.sk0[0].toHex(true),
    );
  });

  it('cannot revoke the old key from an old ciphertext', async () => {
    const before = await openEpochRecord(oldSnapshot, bobEpoch1, oldRecord.checkpoint);
    const still = await openEpochRecord(oldSnapshot, aliceEpoch1, oldRecord.checkpoint);
    expect(before).toMatchObject({ ok: true, plaintext: 'record created in epoch one' });
    expect(still).toMatchObject({ ok: true, plaintext: 'record created in epoch one' });
  });

  it('rewraps only the DEK header and reports zero payload work', async () => {
    expect(rewrappedRecord.payload).toBe(oldRecord.payload);
    expect(bytes(rewrappedRecord.payload.nonce)).toEqual(bytes(oldRecord.payload.nonce));
    expect(bytes(rewrappedRecord.payload.ciphertext)).toEqual(
      bytes(oldRecord.payload.ciphertext),
    );
    expect(bytes(rewrappedRecord.payload.aad)).toEqual(bytes(oldRecord.payload.aad));
    expect(bytes(rewrappedRecord.payload.digest)).toEqual(bytes(oldRecord.payload.digest));
    expect(rewrappedRecord.currentHeader.epoch).toBe(2);
    expect(rewrappedRecord.currentHeader.revision).toBe(2);
    expect(bytes(rewrappedRecord.currentHeader.wrappedDek)).not.toEqual(
      bytes(oldRecord.currentHeader.wrappedDek),
    );

    const opened = await openEpochRecord(
      rewrappedSnapshot,
      aliceEpoch2,
      rewrappedRecord.checkpoint,
    );
    expect(opened).toMatchObject({
      ok: true,
      plaintext: 'record created in epoch one',
      epoch: 2,
      revision: 2,
    });

    const oldKeyAgainstCurrentHeader = await openEpochRecord(
      rewrappedSnapshot,
      bobEpoch1,
      rewrappedRecord.checkpoint,
    );
    expect(oldKeyAgainstCurrentHeader).toMatchObject({
      ok: false,
      code: 'POLICY_UNSATISFIED',
    });

    const costs = costSnapshot(system);
    expect(costs.rewrapOperations).toBe(1);
    expect(costs.ownerDekUnwrapsForRewrap).toBe(1);
    expect(costs.rewrapPayloadBytesWritten).toBe(0);
  });

  it('shows that a retained old key plus retained snapshot still opens', async () => {
    // No checkpoint means no freshness claim.
    const withoutAnchor = await openEpochRecord(oldSnapshot, bobEpoch1, null);
    expect(withoutAnchor).toMatchObject({
      ok: true,
      plaintext: 'record created in epoch one',
      epoch: 1,
    });

    // Rolling the old checkpoint back with the old bytes is equally accepted.
    const rolledBackTogether = await openEpochRecord(
      oldSnapshot,
      bobEpoch1,
      oldRecord.checkpoint,
    );
    expect(rolledBackTogether).toMatchObject({ ok: true, epoch: 1, revision: 1 });
  });

  it('detects the old snapshot only when the newer checkpoint is retained', async () => {
    const detected = await openEpochRecord(
      oldSnapshot,
      bobEpoch1,
      rewrappedRecord.checkpoint,
    );
    expect(detected).toEqual({
      ok: false,
      code: 'ROLLBACK_DETECTED',
      detail:
        'the supplied header does not match the separately trusted epoch/revision/header digest',
    });
  });

  it('keeps owner escrow executable and refuses a wrong owner capability', async () => {
    const ownerOpen = await ownerOpenRecord(owner, rewrappedRecord);
    expect(ownerOpen).toEqual({
      ok: true,
      code: 'OPENED',
      plaintext: 'record created in epoch one',
      objectId: 'record-old',
      contentVersion: 1,
    });

    const wrong = await ownerOpenRecord(wrongOwner, rewrappedRecord);
    expect(wrong).toMatchObject({ ok: false, code: 'AEAD_TAG_REJECTED' });

    const tamperedCapsule: RevocableRecord = {
      ...oldRecord,
      ownerCapsule: {
        ...oldRecord.ownerCapsule,
        wrappedDek: flipped(oldRecord.ownerCapsule.wrappedDek),
      },
    };
    const tampered = await ownerOpenRecord(owner, tamperedCapsule);
    expect(tampered).toMatchObject({ ok: false, code: 'AEAD_TAG_REJECTED' });

    const cannotRewrap = await rewrapEpochRecord(system, wrongOwner, oldRecord);
    expect(cannotRewrap).toMatchObject({
      ok: false,
      code: 'OWNER_CAPSULE_REJECTED',
    });
  });

  it('opens through the owner capsule without trusting an unrelated access header', async () => {
    const crossRecord: RevocableRecord = {
      payload: newRecord.payload,
      ownerCapsule: newRecord.ownerCapsule,
      currentHeader: oldRecord.currentHeader,
      checkpoint: oldRecord.checkpoint,
    };

    const opened = await ownerOpenRecord(owner, crossRecord);
    expect(opened).toEqual({
      ok: true,
      code: 'OPENED',
      plaintext: 'record created after Bob was revoked',
      objectId: 'record-new',
      contentVersion: 1,
    });
    if (opened.ok) {
      expect('epoch' in opened).toBe(false);
      expect('revision' in opened).toBe(false);
    }
  });

  it('keeps authority escrow explicit as mint-then-open', async () => {
    const escrow = await authorityEscrowOpen(system, newSnapshot, newRecord.checkpoint);
    expect(escrow.mintedLabels).toEqual(['Doctor:1', 'Access epoch 2:1']);
    expect(escrow.keyElements).toBe(12);
    expect(escrow.open).toMatchObject({
      ok: true,
      plaintext: 'record created after Bob was revoked',
    });
  });

  it('blocks cross-user pooling even when the union has Doctor and epoch 2', async () => {
    const pooled = poolKeys(carolEpoch2.issued, bobEpoch1.issued);
    expect(pooled.key.labels).toContain('Doctor:1');
    expect(pooled.key.labels).toContain('Access epoch 2:1');

    const opened = await openEpochRecord(newSnapshot, pooled.key, newRecord.checkpoint);
    // The union satisfies the policy, so this is not a superficial label refusal.
    expect(opened).toMatchObject({ ok: false, code: 'AEAD_TAG_REJECTED' });
  });

  it('distinguishes pre-AEAD binding failures from an actual GCM tag failure', async () => {
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      const changedRevision: StoredSnapshot = {
        payload: oldSnapshot.payload,
        accessHeader: { ...oldSnapshot.accessHeader, revision: 2 },
      };
      const revisionResult = await openEpochRecord(changedRevision, bobEpoch1, null);
      expect(revisionResult).toMatchObject({
        ok: false,
        code: 'RECORD_INTEGRITY_REJECTED',
      });
      expect(decrypt).not.toHaveBeenCalled();

      const changedPayload: StoredSnapshot = {
        payload: {
          ...oldSnapshot.payload,
          ciphertext: flipped(oldSnapshot.payload.ciphertext),
        },
        accessHeader: oldSnapshot.accessHeader,
      };
      const payloadResult = await openEpochRecord(changedPayload, bobEpoch1, null);
      expect(payloadResult).toMatchObject({
        ok: false,
        code: 'RECORD_INTEGRITY_REJECTED',
      });
      expect(decrypt).not.toHaveBeenCalled();

      const changedWrap: StoredSnapshot = {
        payload: oldSnapshot.payload,
        accessHeader: {
          ...oldSnapshot.accessHeader,
          wrappedDek: flipped(oldSnapshot.accessHeader.wrappedDek),
        },
      };
      const wrapResult = await openEpochRecord(changedWrap, bobEpoch1, null);
      expect(wrapResult).toMatchObject({ ok: false, code: 'AEAD_TAG_REJECTED' });
      expect(decrypt).toHaveBeenCalledTimes(1);

      const mismatchedObject: StoredSnapshot = {
        payload: { ...oldSnapshot.payload, objectId: 'different-record' },
        accessHeader: oldSnapshot.accessHeader,
      };
      const objectResult = await openEpochRecord(mismatchedObject, bobEpoch1, null);
      expect(objectResult).toMatchObject({ ok: false, code: 'MALFORMED_SNAPSHOT' });
      expect(decrypt).toHaveBeenCalledTimes(1);
    } finally {
      decrypt.mockRestore();
    }
  });

  it('rejects malformed snapshot crypto shapes before any WebCrypto decrypt', async () => {
    const cases: Array<{
      readonly name: string;
      readonly snapshot: StoredSnapshot;
      readonly checkpoint: RevocableRecord['checkpoint'] | null;
    }> = [
      ...[0, 11, 13].map((length) => ({
        name: `payload nonce length ${length}`,
        snapshot: {
          payload: { ...oldSnapshot.payload, nonce: new Uint8Array(length) },
          accessHeader: oldSnapshot.accessHeader,
        },
        checkpoint: null,
      })),
      ...[0, 11, 13].map((length) => ({
        name: `access-header nonce length ${length}`,
        snapshot: {
          payload: oldSnapshot.payload,
          accessHeader: {
            ...oldSnapshot.accessHeader,
            wrappedDekNonce: new Uint8Array(length),
          },
        },
        checkpoint: null,
      })),
      ...[0, 15].map((length) => ({
        name: `payload ciphertext length ${length}`,
        snapshot: {
          payload: { ...oldSnapshot.payload, ciphertext: new Uint8Array(length) },
          accessHeader: oldSnapshot.accessHeader,
        },
        checkpoint: null,
      })),
      ...[0, 47, 49].map((length) => ({
        name: `access-header wrapped-DEK length ${length}`,
        snapshot: {
          payload: oldSnapshot.payload,
          accessHeader: {
            ...oldSnapshot.accessHeader,
            wrappedDek: new Uint8Array(length),
          },
        },
        checkpoint: null,
      })),
      ...[31, 33].map((length) => ({
        name: `payload digest length ${length}`,
        snapshot: {
          payload: { ...oldSnapshot.payload, digest: new Uint8Array(length) },
          accessHeader: oldSnapshot.accessHeader,
        },
        checkpoint: null,
      })),
      ...[31, 33].map((length) => ({
        name: `access-header payload-digest length ${length}`,
        snapshot: {
          payload: oldSnapshot.payload,
          accessHeader: {
            ...oldSnapshot.accessHeader,
            payloadDigest: new Uint8Array(length),
          },
        },
        checkpoint: null,
      })),
      ...[31, 33].map((length) => ({
        name: `checkpoint digest length ${length}`,
        snapshot: oldSnapshot,
        checkpoint: {
          ...oldRecord.checkpoint,
          headerDigest: new Uint8Array(length),
        },
      })),
    ];

    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      for (const testCase of cases) {
        decrypt.mockClear();
        const opened = await openEpochRecord(
          testCase.snapshot,
          bobEpoch1,
          testCase.checkpoint,
        );
        expect(opened, testCase.name).toMatchObject({
          ok: false,
          code: 'MALFORMED_SNAPSHOT',
        });
        expect(decrypt, testCase.name).not.toHaveBeenCalled();
      }
    } finally {
      decrypt.mockRestore();
    }
  });

  it('rejects malformed FAME ciphertext shapes before decryption', async () => {
    const valid = oldSnapshot.accessHeader.ciphertext;
    const firstRow = valid.ct[0];
    const withCiphertext = (ciphertext: unknown): StoredSnapshot => ({
      payload: oldSnapshot.payload,
      accessHeader: {
        ...oldSnapshot.accessHeader,
        ciphertext: ciphertext as typeof valid,
      },
    });
    const withFirstRow = (row: unknown): typeof valid => ({
      ...valid,
      ct: [row, ...valid.ct.slice(1)] as unknown as typeof valid.ct,
    });
    const cases: Array<{ readonly name: string; readonly snapshot: StoredSnapshot }> = [
      {
        name: 'empty ct0',
        snapshot: withCiphertext({ ...valid, ct0: [] }),
      },
      {
        name: 'short ct0',
        snapshot: withCiphertext({ ...valid, ct0: valid.ct0.slice(0, 2) }),
      },
      {
        name: 'long ct0',
        snapshot: withCiphertext({ ...valid, ct0: [...valid.ct0, valid.ct0[0]] }),
      },
      {
        name: 'missing ciphertext row',
        snapshot: withCiphertext({ ...valid, ct: valid.ct.slice(0, -1) }),
      },
      {
        name: 'extra ciphertext row',
        snapshot: withCiphertext({ ...valid, ct: [...valid.ct, valid.ct[0]] }),
      },
      {
        name: 'MSP row count differs from the declared policy',
        snapshot: withCiphertext({
          ...valid,
          msp: { ...valid.msp, rows: valid.msp.rows.slice(0, -1) },
        }),
      },
      {
        name: 'empty ciphertext triple',
        snapshot: withCiphertext(withFirstRow([])),
      },
      {
        name: 'short ciphertext triple',
        snapshot: withCiphertext(withFirstRow(firstRow.slice(0, 2))),
      },
      {
        name: 'long ciphertext triple',
        snapshot: withCiphertext(withFirstRow([...firstRow, firstRow[0]])),
      },
      {
        name: 'missing G2 point',
        snapshot: withCiphertext({
          ...valid,
          ct0: [valid.ct0[0], undefined, valid.ct0[2]],
        }),
      },
      {
        name: 'G1 point in ct0',
        snapshot: withCiphertext({
          ...valid,
          ct0: [firstRow[0], valid.ct0[1], valid.ct0[2]],
        }),
      },
      {
        name: 'plain object in G1 triple',
        snapshot: withCiphertext(
          withFirstRow([firstRow[0], {}, firstRow[2]]),
        ),
      },
      {
        name: 'G2 point in G1 triple',
        snapshot: withCiphertext(
          withFirstRow([firstRow[0], valid.ct0[0], firstRow[2]]),
        ),
      },
      {
        name: 'point-shaped object with unusable G1 internals',
        snapshot: withCiphertext(
          withFirstRow([
            Object.create(Object.getPrototypeOf(firstRow[0])) as unknown,
            firstRow[1],
            firstRow[2],
          ]),
        ),
      },
      {
        name: 'missing target-group element',
        snapshot: withCiphertext({ ...valid, ctPrime: undefined }),
      },
      {
        name: 'plain object as target-group element',
        snapshot: withCiphertext({ ...valid, ctPrime: {} }),
      },
    ];

    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      for (const testCase of cases) {
        decrypt.mockClear();
        const opened = await openEpochRecord(testCase.snapshot, bobEpoch1, null);
        expect(opened, testCase.name).toMatchObject({
          ok: false,
          code: 'MALFORMED_SNAPSHOT',
        });
        expect(decrypt, testCase.name).not.toHaveBeenCalled();
      }
    } finally {
      decrypt.mockRestore();
    }
  });

  it('rejects malformed owner crypto shapes before decrypt but tests real tag failures', async () => {
    const cases: Array<{ readonly name: string; readonly record: RevocableRecord }> = [
      ...[0, 11, 13].map((length) => ({
        name: `payload nonce length ${length}`,
        record: {
          ...oldRecord,
          payload: { ...oldRecord.payload, nonce: new Uint8Array(length) },
        },
      })),
      ...[0, 11, 13].map((length) => ({
        name: `owner-capsule nonce length ${length}`,
        record: {
          ...oldRecord,
          ownerCapsule: {
            ...oldRecord.ownerCapsule,
            nonce: new Uint8Array(length),
          },
        },
      })),
      ...[0, 15].map((length) => ({
        name: `payload ciphertext length ${length}`,
        record: {
          ...oldRecord,
          payload: { ...oldRecord.payload, ciphertext: new Uint8Array(length) },
        },
      })),
      ...[0, 47, 49].map((length) => ({
        name: `owner-capsule wrapped-DEK length ${length}`,
        record: {
          ...oldRecord,
          ownerCapsule: {
            ...oldRecord.ownerCapsule,
            wrappedDek: new Uint8Array(length),
          },
        },
      })),
      ...[31, 33].map((length) => ({
        name: `owner-capsule payload-digest length ${length}`,
        record: {
          ...oldRecord,
          ownerCapsule: {
            ...oldRecord.ownerCapsule,
            payloadDigest: new Uint8Array(length),
          },
        },
      })),
    ];

    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      for (const testCase of cases) {
        decrypt.mockClear();
        const opened = await ownerOpenRecord(owner, testCase.record);
        expect(opened, testCase.name).toMatchObject({
          ok: false,
          code: 'MALFORMED_SNAPSHOT',
        });
        expect(decrypt, testCase.name).not.toHaveBeenCalled();
      }

      decrypt.mockClear();
      const sameLengthBitFlip: RevocableRecord = {
        ...oldRecord,
        ownerCapsule: {
          ...oldRecord.ownerCapsule,
          wrappedDek: flipped(oldRecord.ownerCapsule.wrappedDek),
        },
      };
      const tagFailure = await ownerOpenRecord(owner, sameLengthBitFlip);
      expect(tagFailure).toMatchObject({ ok: false, code: 'AEAD_TAG_REJECTED' });
      expect(decrypt).toHaveBeenCalledTimes(1);
    } finally {
      decrypt.mockRestore();
    }
  });

  it('classifies malformed rewrap inputs without attempting owner decryption', async () => {
    const cases: Array<{
      readonly name: string;
      readonly record: RevocableRecord;
      readonly code:
        | 'SOURCE_RECORD_REJECTED'
        | 'OWNER_CAPSULE_REJECTED'
        | 'SOURCE_CHECKPOINT_REJECTED';
    }> = [
      {
        name: 'malformed payload',
        record: {
          ...oldRecord,
          payload: { ...oldRecord.payload, nonce: new Uint8Array(11) },
        },
        code: 'SOURCE_RECORD_REJECTED',
      },
      {
        name: 'malformed access header',
        record: {
          ...oldRecord,
          currentHeader: {
            ...oldRecord.currentHeader,
            wrappedDek: new Uint8Array(47),
          },
        },
        code: 'SOURCE_RECORD_REJECTED',
      },
      {
        name: 'malformed FAME ciphertext',
        record: {
          ...oldRecord,
          currentHeader: {
            ...oldRecord.currentHeader,
            ciphertext: {
              ...oldRecord.currentHeader.ciphertext,
              ct0: [] as unknown as typeof oldRecord.currentHeader.ciphertext.ct0,
            },
          },
        },
        code: 'SOURCE_RECORD_REJECTED',
      },
      {
        name: 'malformed owner capsule',
        record: {
          ...oldRecord,
          ownerCapsule: {
            ...oldRecord.ownerCapsule,
            nonce: new Uint8Array(13),
          },
        },
        code: 'OWNER_CAPSULE_REJECTED',
      },
      {
        name: 'malformed checkpoint',
        record: {
          ...oldRecord,
          checkpoint: {
            ...oldRecord.checkpoint,
            headerDigest: new Uint8Array(31),
          },
        },
        code: 'SOURCE_CHECKPOINT_REJECTED',
      },
    ];

    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      for (const testCase of cases) {
        decrypt.mockClear();
        const outcome = await rewrapEpochRecord(system, owner, testCase.record);
        expect(outcome, testCase.name).toMatchObject({
          ok: false,
          code: testCase.code,
        });
        expect(decrypt, testCase.name).not.toHaveBeenCalled();
      }
    } finally {
      decrypt.mockRestore();
    }
  });

  it('refuses a stale source checkpoint and a same-epoch pseudo-update', async () => {
    const staleCheckpointRecord: RevocableRecord = {
      ...oldRecord,
      checkpoint: {
        ...oldRecord.checkpoint,
        headerDigest: flipped(oldRecord.checkpoint.headerDigest),
      },
    };
    const stale = await rewrapEpochRecord(system, owner, staleCheckpointRecord);
    expect(stale).toMatchObject({ ok: false, code: 'SOURCE_CHECKPOINT_REJECTED' });

    const sameEpoch = await rewrapEpochRecord(system, owner, rewrappedRecord);
    expect(sameEpoch).toMatchObject({ ok: false, code: 'EPOCH_NOT_ADVANCED' });
  });

  it('rejects cross-record source splices before carrying a DEK into another policy', async () => {
    // Both records have a valid capsule under the same owner. Header/checkpoint
    // A and payload/capsule B are each authentic in isolation, but they are not
    // one record and B must not inherit A's policy during rewrap.
    const crossRecord: RevocableRecord = {
      payload: newRecord.payload,
      ownerCapsule: newRecord.ownerCapsule,
      currentHeader: oldRecord.currentHeader,
      checkpoint: oldRecord.checkpoint,
    };
    const result = await rewrapEpochRecord(system, owner, crossRecord);
    expect(result).toEqual({
      ok: false,
      code: 'SOURCE_RECORD_REJECTED',
      detail: 'payload and current header identify different objects or content versions',
    });
  });

  it('rejects malformed source joins even when their modified header is re-checkpointed', async () => {
    const changedVersionHeader = {
      ...oldRecord.currentHeader,
      contentVersion: oldRecord.currentHeader.contentVersion + 1,
    };
    const changedVersion: RevocableRecord = {
      ...oldRecord,
      currentHeader: changedVersionHeader,
      checkpoint: {
        objectId: changedVersionHeader.objectId,
        epoch: changedVersionHeader.epoch,
        revision: changedVersionHeader.revision,
        headerDigest: computeAccessHeaderDigest(changedVersionHeader),
      },
    };
    expect(await rewrapEpochRecord(system, owner, changedVersion)).toMatchObject({
      ok: false,
      code: 'SOURCE_RECORD_REJECTED',
      detail: 'payload and current header identify different objects or content versions',
    });

    const changedDigestHeader = {
      ...oldRecord.currentHeader,
      payloadDigest: flipped(oldRecord.currentHeader.payloadDigest),
    };
    const changedDigest: RevocableRecord = {
      ...oldRecord,
      currentHeader: changedDigestHeader,
      checkpoint: {
        objectId: changedDigestHeader.objectId,
        epoch: changedDigestHeader.epoch,
        revision: changedDigestHeader.revision,
        headerDigest: computeAccessHeaderDigest(changedDigestHeader),
      },
    };
    expect(await rewrapEpochRecord(system, owner, changedDigest)).toMatchObject({
      ok: false,
      code: 'SOURCE_RECORD_REJECTED',
      detail: 'current header is bound to a different payload digest',
    });

    const staleExpressionHeader = {
      ...oldRecord.currentHeader,
      businessExpression: 'Doctor OR Nurse',
    };
    const structurallyInvalid: RevocableRecord = {
      ...oldRecord,
      currentHeader: staleExpressionHeader,
      checkpoint: {
        objectId: staleExpressionHeader.objectId,
        epoch: staleExpressionHeader.epoch,
        revision: staleExpressionHeader.revision,
        headerDigest: computeAccessHeaderDigest(staleExpressionHeader),
      },
    };
    expect(await rewrapEpochRecord(system, owner, structurallyInvalid)).toMatchObject({
      ok: false,
      code: 'SOURCE_RECORD_REJECTED',
      detail: 'business-policy display string is stale',
    });
  });

  it('does not relabel unexpected WebCrypto failures as tag rejection', async () => {
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
    try {
      decrypt.mockRejectedValueOnce(new TypeError('synthetic WebCrypto wiring failure'));
      await expect(
        openEpochRecord(newSnapshot, aliceEpoch2, newRecord.checkpoint),
      ).rejects.toThrow('synthetic WebCrypto wiring failure');

      decrypt.mockRejectedValueOnce(new TypeError('synthetic owner unwrap failure'));
      await expect(rewrapEpochRecord(system, owner, oldRecord)).rejects.toThrow(
        'synthetic owner unwrap failure',
      );
    } finally {
      decrypt.mockRestore();
    }
  });

  it('independently verifies both SHA-256 checkpoint digests with WebCrypto', async () => {
    const headerDigest = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        encodeAccessHeader(rewrappedRecord.currentHeader) as BufferSource,
      ),
    );
    expect(bytes(headerDigest)).toEqual(bytes(rewrappedRecord.checkpoint.headerDigest));
    expect(bytes(computeAccessHeaderDigest(rewrappedRecord.currentHeader))).toEqual(
      bytes(headerDigest),
    );

    const payloadDigest = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        encodePayloadCiphertext(rewrappedRecord.payload) as BufferSource,
      ),
    );
    expect(bytes(payloadDigest)).toEqual(bytes(rewrappedRecord.payload.digest));
  });

  it('derives the cost ledger from completed operations', () => {
    const costs = costSnapshot(system);
    expect(costs).toMatchObject({
      epochAdvances: 1,
      revocations: 1,
      holderKeyGenerations: 4,
      authorityEscrowKeyGenerations: 1,
      fameHeaderEncryptions: 3,
      payloadAeadEncryptions: 2,
      ownerCapsuleEncryptions: 2,
      ownerDekUnwrapsForRewrap: 1,
      accessDekWraps: 3,
      checkpointWrites: 3,
      rewrapOperations: 1,
      rewrapPayloadBytesWritten: 0,
    });
    expect(costs.payloadPlaintextBytesEncrypted).toBe(
      new TextEncoder().encode('record created in epoch one').length +
        new TextEncoder().encode('record created after Bob was revoked').length,
    );
    expect(costs.accessHeaderBytesWritten).toBeGreaterThan(0);
  });
});
