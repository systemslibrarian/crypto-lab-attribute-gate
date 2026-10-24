/**
 * Bounded epoch gating and owner-assisted DEK rewrap.
 *
 * This module is deliberately an APPLICATION-LAYER ADAPTATION around the
 * existing single-authority FAME implementation.  It is not RW15, is not a
 * revocable-ABE or revocable-storage-ABE construction, and has no combined
 * security theorem.  In particular, ciphertext update is not public: an
 * owner capability must recover each selected record's data-encryption key
 * (DEK) before a new FAME access header can be made.
 *
 * The executable boundary is:
 *
 *   plaintext --AES-256-GCM under fresh DEK--> immutable payload
 *   DEK       --owner AES-256-GCM-----------> owner recovery capsule
 *   random GT --FAME under policy AND epoch-> access ciphertext
 *   DEK       --AES-256-GCM under GT/HKDF---> epoch access capsule
 *
 * Advancing an epoch reissues a COMPLETE FAME key to every active holder;
 * FAME does not expose an independently updateable epoch component.  Rewrap
 * changes only the access header.  A revoked holder who retained the previous
 * key and header can still open the unchanged payload.  A trusted checkpoint
 * detects a stale header, but AES-GCM alone does not provide freshness and a
 * checkpoint rolled back with the ciphertext detects nothing.
 */
import {
  G1_BYTES,
  G2_BYTES,
  GT_BYTES,
  g1,
  g1ToHex,
  g2,
  g2ToHex,
  gtToBytes,
  type G1Point,
  type G2Point,
  type GTElement,
} from '../fame/bls';
import {
  decrypt,
  encrypt,
  keygen,
  randomGT,
  setup,
  type Authority,
  type Ciphertext,
  type IssuedKey,
  type SecretKey,
} from '../fame/fame';
import { aesGcmEncrypt, hkdfSha256 } from '../fame/kem';
import { minimalSatisfyingLabels, policyToMsp, type Msp } from '../fame/msp';
import { AttributeRegistry } from '../fame/oneuse';
import {
  formatPolicy,
  leavesOf,
  validatePolicy,
  type PolicyNode,
} from '../fame/policy';
import { secureRandom, type RandomSource } from '../fame/rand';
import {
  bytesEqual,
  cloneBytes,
  decimal,
  digest,
  frame,
  hexToBytes,
  u32be,
  utf8,
} from './encoding';

const ACCESS_EPOCH_PREFIX = 'Access epoch ';
const MAX_IDENTIFIER_BYTES = 96;
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const SHA256_BYTES = 32;
const ACCESS_HKDF_SALT = utf8('crypto-lab-attribute-gate/epoch-access/salt/v1');
const ACCESS_HKDF_INFO = utf8('crypto-lab-attribute-gate/epoch-access/DEK-wrap/v1');
const decoder = new TextDecoder('utf-8', { fatal: true });

/* -------------------------------------------------------------------------- */
/* Public state and result types                                              */
/* -------------------------------------------------------------------------- */

export interface Holder {
  readonly id: string;
  readonly attributes: readonly string[];
}

export interface CostLedger {
  readonly epochAdvances: number;
  readonly revocations: number;
  readonly holderKeyGenerations: number;
  readonly authorityEscrowKeyGenerations: number;
  readonly fameHeaderEncryptions: number;
  readonly payloadAeadEncryptions: number;
  readonly payloadPlaintextBytesEncrypted: number;
  readonly ownerCapsuleEncryptions: number;
  readonly ownerDekUnwrapsForRewrap: number;
  readonly accessDekWraps: number;
  readonly accessHeaderBytesWritten: number;
  readonly checkpointWrites: number;
  readonly rewrapOperations: number;
  /** Must remain zero: a rewrap replaces the DEK header, not the payload. */
  readonly rewrapPayloadBytesWritten: number;
}

interface MutableCostLedger {
  epochAdvances: number;
  revocations: number;
  holderKeyGenerations: number;
  authorityEscrowKeyGenerations: number;
  fameHeaderEncryptions: number;
  payloadAeadEncryptions: number;
  payloadPlaintextBytesEncrypted: number;
  ownerCapsuleEncryptions: number;
  ownerDekUnwrapsForRewrap: number;
  accessDekWraps: number;
  accessHeaderBytesWritten: number;
  checkpointWrites: number;
  rewrapOperations: number;
  rewrapPayloadBytesWritten: number;
}

export interface EpochSystem {
  readonly authority: Authority;
  readonly registry: AttributeRegistry;
  readonly rng: RandomSource;
  currentEpoch: number;
  /** Internal model state; mutate through revokeHolder. */
  readonly revokedHolders: Set<string>;
  /** Internal monotonic label source for deterministic fixtures. */
  serial: number;
  /** Internal counters; read a copy through costSnapshot. */
  readonly ledger: MutableCostLedger;
}

export interface EpochKeyRecord {
  readonly holder: string;
  readonly baseAttributes: readonly string[];
  readonly epoch: number;
  readonly issued: IssuedKey;
  readonly elements: number;
  readonly serial: number;
}

export type IssueResult =
  | { readonly ok: true; readonly key: EpochKeyRecord }
  | {
      readonly ok: false;
      readonly code: 'HOLDER_REVOKED';
      readonly detail: string;
    };

export interface OwnerCapability {
  readonly ownerId: string;
  /** Non-extractable WebCrypto key. Possession is an explicit escrow power. */
  readonly key: CryptoKey;
}

export interface PayloadCiphertext {
  readonly objectId: string;
  readonly contentVersion: number;
  readonly nonce: Uint8Array;
  /** WebCrypto's AES-GCM ciphertext with its 128-bit tag appended. */
  readonly ciphertext: Uint8Array;
  readonly aad: Uint8Array;
  readonly digest: Uint8Array;
}

export interface OwnerCapsule {
  readonly ownerId: string;
  readonly objectId: string;
  readonly contentVersion: number;
  readonly payloadDigest: Uint8Array;
  readonly nonce: Uint8Array;
  readonly wrappedDek: Uint8Array;
  readonly aad: Uint8Array;
}

export interface EpochAccessHeader {
  readonly objectId: string;
  readonly contentVersion: number;
  readonly payloadDigest: Uint8Array;
  readonly epoch: number;
  readonly revision: number;
  readonly businessPolicy: PolicyNode;
  readonly gatedPolicy: PolicyNode;
  readonly businessExpression: string;
  readonly gatedExpression: string;
  readonly ciphertext: Ciphertext;
  readonly wrappedDekNonce: Uint8Array;
  readonly wrappedDek: Uint8Array;
  readonly wrapAad: Uint8Array;
}

export interface TrustedCheckpoint {
  readonly objectId: string;
  readonly epoch: number;
  readonly revision: number;
  /** Digest of the complete wire-relevant access header. */
  readonly headerDigest: Uint8Array;
}

export interface RevocableRecord {
  readonly payload: PayloadCiphertext;
  readonly ownerCapsule: OwnerCapsule;
  readonly currentHeader: EpochAccessHeader;
  readonly checkpoint: TrustedCheckpoint;
}

export interface StoredSnapshot {
  readonly payload: PayloadCiphertext;
  readonly accessHeader: EpochAccessHeader;
}

export type OpenFailureCode =
  | 'ROLLBACK_DETECTED'
  | 'POLICY_UNSATISFIED'
  | 'RECORD_INTEGRITY_REJECTED'
  | 'AEAD_TAG_REJECTED'
  | 'MALFORMED_SNAPSHOT';

export interface OpenFailure {
  readonly ok: false;
  readonly code: OpenFailureCode;
  readonly detail: string;
}

export type OpenOutcome =
  | {
      readonly ok: true;
      readonly code: 'OPENED';
      readonly plaintext: string;
      readonly epoch: number;
      readonly revision: number;
    }
  | OpenFailure;

/**
 * Direct owner recovery authenticates the payload and owner capsule only.
 * It deliberately reports no access-header epoch or revision.
 */
export type OwnerOpenOutcome =
  | {
      readonly ok: true;
      readonly code: 'OPENED';
      readonly plaintext: string;
      readonly objectId: string;
      readonly contentVersion: number;
    }
  | OpenFailure;

export interface RewrapWork {
  readonly ownerDekUnwraps: 1;
  readonly fameHeaderEncryptions: 1;
  readonly accessDekWraps: 1;
  readonly accessHeaderBytesWritten: number;
  readonly checkpointWrites: 1;
  readonly payloadEncryptions: 0;
  readonly payloadBytesRewritten: 0;
}

export type RewrapOutcome =
  | {
      readonly ok: true;
      readonly record: RevocableRecord;
      readonly fromEpoch: number;
      readonly toEpoch: number;
      readonly work: RewrapWork;
    }
  | {
      readonly ok: false;
      readonly code:
        | 'OWNER_CAPSULE_REJECTED'
        | 'SOURCE_CHECKPOINT_REJECTED'
        | 'SOURCE_RECORD_REJECTED'
        | 'EPOCH_NOT_ADVANCED';
      readonly detail: string;
    };

export interface AuthorityEscrowOutcome {
  readonly mintedLabels: readonly string[];
  readonly keyElements: number;
  readonly open: OpenOutcome;
}

export type AccessKey = EpochKeyRecord | SecretKey;

/* -------------------------------------------------------------------------- */
/* Model lifecycle                                                            */
/* -------------------------------------------------------------------------- */

function emptyLedger(): MutableCostLedger {
  return {
    epochAdvances: 0,
    revocations: 0,
    holderKeyGenerations: 0,
    authorityEscrowKeyGenerations: 0,
    fameHeaderEncryptions: 0,
    payloadAeadEncryptions: 0,
    payloadPlaintextBytesEncrypted: 0,
    ownerCapsuleEncryptions: 0,
    ownerDekUnwrapsForRewrap: 0,
    accessDekWraps: 0,
    accessHeaderBytesWritten: 0,
    checkpointWrites: 0,
    rewrapOperations: 0,
    rewrapPayloadBytesWritten: 0,
  };
}

function assertEpoch(epoch: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > 0xffff_ffff) {
    throw new Error('INVALID_EPOCH: epoch must be an integer in 1..2^32-1');
  }
}

function assertIdentifier(value: string, field: string): void {
  const encoded = utf8(value);
  if (
    encoded.length === 0 ||
    encoded.length > MAX_IDENTIFIER_BYTES ||
    value !== value.normalize('NFC') ||
    /\p{Cc}/u.test(value)
  ) {
    throw new Error(
      `INVALID_IDENTIFIER: ${field} must be NFC, contain no controls, and encode to 1-${MAX_IDENTIFIER_BYTES} bytes`,
    );
  }
}

export function createEpochSystem(
  rng: RandomSource = secureRandom,
  initialEpoch = 1,
): EpochSystem {
  assertEpoch(initialEpoch);
  return {
    authority: setup(rng),
    registry: new AttributeRegistry(),
    rng,
    currentEpoch: initialEpoch,
    revokedHolders: new Set(),
    serial: 0,
    ledger: emptyLedger(),
  };
}

export async function createOwnerCapability(
  ownerId: string,
  rng: RandomSource = secureRandom,
): Promise<OwnerCapability> {
  assertIdentifier(ownerId, 'owner id');
  const raw = rng.bytes(`revocation:owner-key:${ownerId}`, AES_KEY_BYTES);
  try {
    const key = await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ]);
    return { ownerId, key };
  } finally {
    raw.fill(0);
  }
}

export function epochAttribute(epoch: number): string {
  assertEpoch(epoch);
  return `${ACCESS_EPOCH_PREFIX}${epoch}`;
}

function cloneBusinessPolicy(node: PolicyNode, path = '0'): PolicyNode {
  if (node.kind === 'attribute') {
    return {
      kind: 'attribute',
      id: `revocation/business/${path}/${node.id}`,
      name: node.name,
    };
  }
  return {
    kind: 'threshold',
    id: `revocation/business/${path}/${node.id}`,
    threshold: node.threshold,
    children: node.children.map((child, index) => cloneBusinessPolicy(child, `${path}.${index}`)),
  };
}

/**
 * Build `businessPolicy AND Access epoch N` with fresh node identities.
 * The epoch namespace is reserved so a caller cannot smuggle its own epoch
 * leaf into the business rule and make the visible metadata ambiguous.
 */
export function gatePolicy(businessPolicy: PolicyNode, epoch: number): PolicyNode {
  assertEpoch(epoch);
  validatePolicy(businessPolicy);
  if (leavesOf(businessPolicy).some((leaf) => leaf.name.startsWith(ACCESS_EPOCH_PREFIX))) {
    throw new Error(`RESERVED_ATTRIBUTE: "${ACCESS_EPOCH_PREFIX}" is owned by epoch gating`);
  }
  const gated: PolicyNode = {
    kind: 'threshold',
    id: `revocation/root/${epoch}`,
    threshold: 2,
    children: [
      cloneBusinessPolicy(businessPolicy),
      {
        kind: 'attribute',
        id: `revocation/epoch/${epoch}`,
        name: epochAttribute(epoch),
      },
    ],
  };
  validatePolicy(gated);
  return gated;
}

function validateHolder(holder: Holder): void {
  assertIdentifier(holder.id, 'holder id');
  if (holder.attributes.length === 0) {
    throw new Error('INVALID_HOLDER: at least one business attribute is required');
  }
  if (new Set(holder.attributes).size !== holder.attributes.length) {
    throw new Error('INVALID_HOLDER: duplicate business attributes are not allowed');
  }
  const validationPolicy: PolicyNode = {
    kind: 'threshold',
    id: 'revocation/holder-validation',
    threshold: 1,
    children: holder.attributes.map((name, index) => ({
      kind: 'attribute' as const,
      id: `revocation/holder-validation/${index}`,
      name,
    })),
  };
  validatePolicy(validationPolicy);
  if (holder.attributes.some((name) => name.startsWith(ACCESS_EPOCH_PREFIX))) {
    throw new Error(`RESERVED_ATTRIBUTE: "${ACCESS_EPOCH_PREFIX}" is issued by the model`);
  }
}

export function revokeHolder(system: EpochSystem, holderId: string): boolean {
  assertIdentifier(holderId, 'holder id');
  const before = system.revokedHolders.size;
  system.revokedHolders.add(holderId);
  if (system.revokedHolders.size !== before) {
    system.ledger.revocations += 1;
    return true;
  }
  return false;
}

export function isRevoked(system: EpochSystem, holderId: string): boolean {
  return system.revokedHolders.has(holderId);
}

export function advanceEpoch(system: EpochSystem): { readonly from: number; readonly to: number } {
  const from = system.currentEpoch;
  assertEpoch(from + 1);
  system.currentEpoch = from + 1;
  system.ledger.epochAdvances += 1;
  return { from, to: system.currentEpoch };
}

/**
 * Reissue one complete FAME key for the current epoch.
 *
 * This intentionally is not an epoch-component update.  The holder's business
 * attributes and epoch label share one fresh KeyGen randomization.
 */
export function issueCurrentEpochKey(system: EpochSystem, holder: Holder): IssueResult {
  validateHolder(holder);
  if (system.revokedHolders.has(holder.id)) {
    return {
      ok: false,
      code: 'HOLDER_REVOKED',
      detail: `${holder.id} is on the revocation list and receives no epoch ${system.currentEpoch} key`,
    };
  }

  const names = [...holder.attributes, epochAttribute(system.currentEpoch)];
  const labels = system.registry.expand(names);
  system.serial += 1;
  const { key, witness } = keygen(
    system.authority.msk,
    labels,
    system.rng,
    `revocation:key:${holder.id}:epoch-${system.currentEpoch}:serial-${system.serial}`,
  );
  const copiesAtIssue = new Map(names.map((name) => [name, system.registry.copies(name)]));
  const issued: IssuedKey = {
    holder: `${holder.id}@epoch-${system.currentEpoch}`,
    heldNames: names,
    key,
    witness,
    copiesAtIssue,
  };
  const record: EpochKeyRecord = {
    holder: holder.id,
    baseAttributes: [...holder.attributes],
    epoch: system.currentEpoch,
    issued,
    elements: 3 + 3 * key.sk.size + 3,
    serial: system.serial,
  };
  system.ledger.holderKeyGenerations += 1;
  return { ok: true, key: record };
}

export function costSnapshot(system: EpochSystem): CostLedger {
  return { ...system.ledger };
}

/* -------------------------------------------------------------------------- */
/* Canonical wire-relevant encodings                                          */
/* -------------------------------------------------------------------------- */

function encodePolicy(policy: PolicyNode): Uint8Array {
  if (policy.kind === 'attribute') {
    return frame('CRYPTO-LAB/REVOCATION/POLICY-ATTRIBUTE/v1', [
      utf8(policy.id),
      utf8(policy.name),
    ]);
  }
  return frame('CRYPTO-LAB/REVOCATION/POLICY-THRESHOLD/v1', [
    utf8(policy.id),
    u32be(policy.threshold),
    u32be(policy.children.length),
    ...policy.children.map(encodePolicy),
  ]);
}

function encodeMsp(msp: Msp): Uint8Array {
  const rows = msp.rows.map((row) =>
    frame('CRYPTO-LAB/REVOCATION/MSP-ROW/v1', [
      u32be(row.index),
      utf8(row.leafId),
      utf8(row.name),
      utf8(row.label),
      u32be(row.vector.length),
      ...row.vector.map(decimal),
    ]),
  );
  return frame('CRYPTO-LAB/REVOCATION/MSP/v1', [
    u32be(msp.columns),
    u32be(rows.length),
    ...rows,
    u32be(msp.columnOwner.length),
    ...msp.columnOwner.map((owner) => utf8(owner ?? '')),
  ]);
}

function encodeCiphertext(ciphertext: Ciphertext): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/FAME-CIPHERTEXT/v1', [
    encodePolicy(ciphertext.policy),
    encodeMsp(ciphertext.msp),
    ...ciphertext.ct0.map((point) => hexToBytes(g2ToHex(point))),
    u32be(ciphertext.ct.length),
    ...ciphertext.ct.flatMap((triple) =>
      triple.map((point) => hexToBytes(g1ToHex(point))),
    ),
    gtToBytes(ciphertext.ctPrime),
  ]);
}

function payloadAad(objectId: string, contentVersion: number): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/PAYLOAD-AAD/v1', [
    utf8(objectId),
    u32be(contentVersion),
  ]);
}

export function encodePayloadCiphertext(payload: PayloadCiphertext): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/PAYLOAD/v1', [
    utf8(payload.objectId),
    u32be(payload.contentVersion),
    payload.aad,
    payload.nonce,
    payload.ciphertext,
  ]);
}

export function computePayloadDigest(payload: PayloadCiphertext): Uint8Array {
  return digest(encodePayloadCiphertext(payload));
}

function ownerAad(
  ownerId: string,
  objectId: string,
  contentVersion: number,
  payloadDigest: Uint8Array,
): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/OWNER-CAPSULE-AAD/v1', [
    utf8(ownerId),
    utf8(objectId),
    u32be(contentVersion),
    payloadDigest,
  ]);
}

function accessWrapAad(
  objectId: string,
  contentVersion: number,
  payloadDigest: Uint8Array,
  epoch: number,
  revision: number,
  businessPolicy: PolicyNode,
  gatedPolicy: PolicyNode,
): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/ACCESS-WRAP-AAD/v1', [
    utf8(objectId),
    u32be(contentVersion),
    payloadDigest,
    u32be(epoch),
    u32be(revision),
    encodePolicy(businessPolicy),
    encodePolicy(gatedPolicy),
  ]);
}

export function encodeAccessHeader(header: EpochAccessHeader): Uint8Array {
  return frame('CRYPTO-LAB/REVOCATION/ACCESS-HEADER/v1', [
    utf8(header.objectId),
    u32be(header.contentVersion),
    header.payloadDigest,
    u32be(header.epoch),
    u32be(header.revision),
    utf8(header.businessExpression),
    utf8(header.gatedExpression),
    encodePolicy(header.businessPolicy),
    encodePolicy(header.gatedPolicy),
    encodeCiphertext(header.ciphertext),
    header.wrappedDekNonce,
    header.wrappedDek,
    header.wrapAad,
  ]);
}

export function computeAccessHeaderDigest(header: EpochAccessHeader): Uint8Array {
  return digest(encodeAccessHeader(header));
}

function makeCheckpoint(header: EpochAccessHeader): TrustedCheckpoint {
  return {
    objectId: header.objectId,
    epoch: header.epoch,
    revision: header.revision,
    headerDigest: computeAccessHeaderDigest(header),
  };
}

/* -------------------------------------------------------------------------- */
/* AEAD helpers                                                               */
/* -------------------------------------------------------------------------- */

async function encryptWithCryptoKey(
  key: CryptoKey,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const result = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    key,
    plaintext as BufferSource,
  );
  return new Uint8Array(result);
}

async function decryptWithCryptoKey(
  key: CryptoKey,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const result = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      key,
      ciphertext as BufferSource,
    );
    return new Uint8Array(result);
  } catch (error) {
    // WebCrypto reports an AES-GCM tag failure as OperationError.  That is an
    // expected negative cryptographic outcome.  A TypeError (bad API wiring),
    // NotSupportedError, or any other runtime failure is not evidence that a
    // tag was rejected and must remain visible to the caller.
    if (error instanceof DOMException && error.name === 'OperationError') return null;
    throw error;
  }
}

async function decryptWithRawKey(
  rawKey: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array | null> {
  const key = await crypto.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, [
    'decrypt',
  ]);
  return decryptWithCryptoKey(key, nonce, aad, ciphertext);
}

async function deriveAccessKek(shared: GTElement): Promise<Uint8Array> {
  return hkdfSha256(
    gtToBytes(shared),
    ACCESS_HKDF_SALT,
    ACCESS_HKDF_INFO,
    AES_KEY_BYTES,
  );
}

/* -------------------------------------------------------------------------- */
/* Record creation and header construction                                    */
/* -------------------------------------------------------------------------- */

async function makeAccessHeader(
  system: EpochSystem,
  objectId: string,
  contentVersion: number,
  payloadDigest: Uint8Array,
  businessPolicy: PolicyNode,
  epoch: number,
  revision: number,
  dek: Uint8Array,
): Promise<EpochAccessHeader> {
  const gatedPolicy = gatePolicy(businessPolicy, epoch);
  system.registry.observePolicy(gatedPolicy);
  const msp = policyToMsp(gatedPolicy);
  system.serial += 1;
  const nonceLabel = `revocation:header:${objectId}:epoch-${epoch}:revision-${revision}:serial-${system.serial}`;
  const { element } = randomGT(system.rng, `${nonceLabel}:gt`);
  const { ciphertext } = encrypt(
    system.authority.pk,
    gatedPolicy,
    msp,
    element,
    system.rng,
    nonceLabel,
  );
  const wrapAad = accessWrapAad(
    objectId,
    contentVersion,
    payloadDigest,
    epoch,
    revision,
    businessPolicy,
    gatedPolicy,
  );
  const wrappedDekNonce = system.rng.bytes(`${nonceLabel}:dek-wrap-nonce`, GCM_NONCE_BYTES);
  const accessKek = await deriveAccessKek(element);
  let wrappedDek: Uint8Array;
  try {
    wrappedDek = await aesGcmEncrypt(accessKek, wrappedDekNonce, wrapAad, dek);
  } finally {
    accessKek.fill(0);
  }
  return {
    objectId,
    contentVersion,
    payloadDigest: cloneBytes(payloadDigest),
    epoch,
    revision,
    businessPolicy,
    gatedPolicy,
    businessExpression: formatPolicy(businessPolicy),
    gatedExpression: formatPolicy(gatedPolicy),
    ciphertext,
    wrappedDekNonce,
    wrappedDek,
    wrapAad,
  };
}

export async function sealEpochRecord(
  system: EpochSystem,
  owner: OwnerCapability,
  objectId: string,
  businessPolicy: PolicyNode,
  plaintext: string,
): Promise<RevocableRecord> {
  assertIdentifier(objectId, 'object id');
  const contentVersion = 1;
  const operation = ++system.serial;
  const dek = system.rng.bytes(`revocation:payload:${objectId}:dek:${operation}`, AES_KEY_BYTES);
  try {
    const aad = payloadAad(objectId, contentVersion);
    const nonce = system.rng.bytes(
      `revocation:payload:${objectId}:nonce:${operation}`,
      GCM_NONCE_BYTES,
    );
    const plaintextBytes = utf8(plaintext);
    const ciphertext = await aesGcmEncrypt(dek, nonce, aad, plaintextBytes);
    const incompletePayload = { objectId, contentVersion, nonce, ciphertext, aad };
    const payload: PayloadCiphertext = {
      ...incompletePayload,
      digest: digest(
        encodePayloadCiphertext({
          ...incompletePayload,
          digest: new Uint8Array(),
        }),
      ),
    };

    const ownerCapsuleAad = ownerAad(
      owner.ownerId,
      objectId,
      contentVersion,
      payload.digest,
    );
    const ownerNonce = system.rng.bytes(
      `revocation:owner-capsule:${objectId}:nonce:${operation}`,
      GCM_NONCE_BYTES,
    );
    const ownerCapsule: OwnerCapsule = {
      ownerId: owner.ownerId,
      objectId,
      contentVersion,
      payloadDigest: cloneBytes(payload.digest),
      nonce: ownerNonce,
      wrappedDek: await encryptWithCryptoKey(owner.key, ownerNonce, ownerCapsuleAad, dek),
      aad: ownerCapsuleAad,
    };

    const currentHeader = await makeAccessHeader(
      system,
      objectId,
      contentVersion,
      payload.digest,
      businessPolicy,
      system.currentEpoch,
      1,
      dek,
    );
    const checkpoint = makeCheckpoint(currentHeader);
    const headerBytes = encodeAccessHeader(currentHeader).length;

    system.ledger.payloadAeadEncryptions += 1;
    system.ledger.payloadPlaintextBytesEncrypted += plaintextBytes.length;
    system.ledger.ownerCapsuleEncryptions += 1;
    system.ledger.fameHeaderEncryptions += 1;
    system.ledger.accessDekWraps += 1;
    system.ledger.accessHeaderBytesWritten += headerBytes;
    system.ledger.checkpointWrites += 1;

    return { payload, ownerCapsule, currentHeader, checkpoint };
  } finally {
    dek.fill(0);
  }
}

function clonePayload(payload: PayloadCiphertext): PayloadCiphertext {
  return {
    ...payload,
    nonce: cloneBytes(payload.nonce),
    ciphertext: cloneBytes(payload.ciphertext),
    aad: cloneBytes(payload.aad),
    digest: cloneBytes(payload.digest),
  };
}

function cloneHeader(header: EpochAccessHeader): EpochAccessHeader {
  return {
    ...header,
    payloadDigest: cloneBytes(header.payloadDigest),
    wrappedDekNonce: cloneBytes(header.wrappedDekNonce),
    wrappedDek: cloneBytes(header.wrappedDek),
    wrapAad: cloneBytes(header.wrapAad),
  };
}

export function takeStorageSnapshot(record: RevocableRecord): StoredSnapshot {
  return {
    payload: clonePayload(record.payload),
    accessHeader: cloneHeader(record.currentHeader),
  };
}

/* -------------------------------------------------------------------------- */
/* Validation and opening                                                     */
/* -------------------------------------------------------------------------- */

function malformed(detail: string): OpenFailure {
  return { ok: false, code: 'MALFORMED_SNAPSHOT', detail };
}

function tagRejected(detail: string): OpenFailure {
  return { ok: false, code: 'AEAD_TAG_REJECTED', detail };
}

function integrityRejected(detail: string): OpenFailure {
  return { ok: false, code: 'RECORD_INTEGRITY_REJECTED', detail };
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function validateContentVersion(contentVersion: number): string | null {
  return Number.isSafeInteger(contentVersion) &&
    contentVersion >= 1 &&
    contentVersion <= 0xffff_ffff
    ? null
    : 'content version is outside uint32';
}

/**
 * Validate the byte-level shape promised by this teaching model before any
 * value can reach WebCrypto. These checks do not authenticate bytes; they only
 * keep malformed encodings distinct from an attempted GCM tag check.
 */
function validatePayloadShape(payload: PayloadCiphertext): string | null {
  try {
    assertIdentifier(payload.objectId, 'object id');
  } catch (error) {
    return error instanceof Error ? error.message : 'payload identifier validation failed';
  }
  const versionError = validateContentVersion(payload.contentVersion);
  if (versionError !== null) return versionError;
  if (!isBytes(payload.nonce) || payload.nonce.length !== GCM_NONCE_BYTES) {
    return `payload AES-GCM nonce must be exactly ${GCM_NONCE_BYTES} bytes`;
  }
  if (!isBytes(payload.ciphertext) || payload.ciphertext.length < GCM_TAG_BYTES) {
    return `payload AES-GCM ciphertext must contain at least the ${GCM_TAG_BYTES}-byte tag`;
  }
  if (!isBytes(payload.aad)) return 'payload AAD must be a byte string';
  if (!isBytes(payload.digest) || payload.digest.length !== SHA256_BYTES) {
    return `payload digest must be exactly ${SHA256_BYTES} bytes`;
  }
  return null;
}

function validateAccessHeaderShape(header: EpochAccessHeader): string | null {
  if (!isBytes(header.payloadDigest) || header.payloadDigest.length !== SHA256_BYTES) {
    return `access-header payload digest must be exactly ${SHA256_BYTES} bytes`;
  }
  if (
    !isBytes(header.wrappedDekNonce) ||
    header.wrappedDekNonce.length !== GCM_NONCE_BYTES
  ) {
    return `access-header AES-GCM nonce must be exactly ${GCM_NONCE_BYTES} bytes`;
  }
  if (
    !isBytes(header.wrappedDek) ||
    header.wrappedDek.length !== AES_KEY_BYTES + GCM_TAG_BYTES
  ) {
    return `access-header wrapped DEK must be exactly ${AES_KEY_BYTES + GCM_TAG_BYTES} bytes`;
  }
  if (!isBytes(header.wrapAad)) return 'access-header AAD must be a byte string';
  return validateHeaderStructure(header);
}

function validateOwnerCapsuleShape(capsule: OwnerCapsule): string | null {
  try {
    assertIdentifier(capsule.ownerId, 'owner id');
    assertIdentifier(capsule.objectId, 'object id');
  } catch (error) {
    return error instanceof Error ? error.message : 'owner-capsule identifier validation failed';
  }
  const versionError = validateContentVersion(capsule.contentVersion);
  if (versionError !== null) return versionError;
  if (!isBytes(capsule.payloadDigest) || capsule.payloadDigest.length !== SHA256_BYTES) {
    return `owner-capsule payload digest must be exactly ${SHA256_BYTES} bytes`;
  }
  if (!isBytes(capsule.nonce) || capsule.nonce.length !== GCM_NONCE_BYTES) {
    return `owner-capsule AES-GCM nonce must be exactly ${GCM_NONCE_BYTES} bytes`;
  }
  if (
    !isBytes(capsule.wrappedDek) ||
    capsule.wrappedDek.length !== AES_KEY_BYTES + GCM_TAG_BYTES
  ) {
    return `owner-capsule wrapped DEK must be exactly ${AES_KEY_BYTES + GCM_TAG_BYTES} bytes`;
  }
  if (!isBytes(capsule.aad)) return 'owner-capsule AAD must be a byte string';
  return null;
}

function validateCheckpointShape(checkpoint: TrustedCheckpoint): string | null {
  try {
    assertIdentifier(checkpoint.objectId, 'checkpoint object id');
    assertEpoch(checkpoint.epoch);
  } catch (error) {
    return error instanceof Error ? error.message : 'checkpoint identifier validation failed';
  }
  if (
    !Number.isSafeInteger(checkpoint.revision) ||
    checkpoint.revision < 1 ||
    checkpoint.revision > 0xffff_ffff
  ) {
    return 'checkpoint revision is outside uint32';
  }
  if (!isBytes(checkpoint.headerDigest) || checkpoint.headerDigest.length !== SHA256_BYTES) {
    return `checkpoint header digest must be exactly ${SHA256_BYTES} bytes`;
  }
  return null;
}

function validateG1PointRuntime(point: unknown, field: string): string | null {
  try {
    if (
      typeof point !== 'object' ||
      point === null ||
      Object.getPrototypeOf(point) !== Object.getPrototypeOf(g1)
    ) {
      return `${field} is not a runtime G1 point`;
    }
    const candidate = point as G1Point;
    candidate.assertValidity();
    if (g1ToHex(candidate).length !== G1_BYTES * 2) {
      return `${field} does not have the canonical G1 encoding length`;
    }
    return null;
  } catch {
    return `${field} is not a valid runtime G1 point`;
  }
}

function validateG2PointRuntime(point: unknown, field: string): string | null {
  try {
    if (
      typeof point !== 'object' ||
      point === null ||
      Object.getPrototypeOf(point) !== Object.getPrototypeOf(g2)
    ) {
      return `${field} is not a runtime G2 point`;
    }
    const candidate = point as G2Point;
    candidate.assertValidity();
    if (g2ToHex(candidate).length !== G2_BYTES * 2) {
      return `${field} does not have the canonical G2 encoding length`;
    }
    return null;
  } catch {
    return `${field} is not a valid runtime G2 point`;
  }
}

function validateGtRuntime(element: unknown, field: string): string | null {
  try {
    const encoded = gtToBytes(element as GTElement);
    return encoded.length === GT_BYTES
      ? null
      : `${field} does not have the canonical GT encoding length`;
  } catch {
    return `${field} is not a valid runtime GT element`;
  }
}

function validateFameCiphertextShape(
  ciphertext: unknown,
  expectedRows: number,
): string | null {
  if (typeof ciphertext !== 'object' || ciphertext === null) {
    return 'FAME ciphertext must be an object';
  }
  const candidate = ciphertext as Record<string, unknown>;
  if (!Array.isArray(candidate.ct0) || candidate.ct0.length !== 3) {
    return 'FAME ct0 must contain exactly three G2 points';
  }
  for (let index = 0; index < candidate.ct0.length; index += 1) {
    const pointError = validateG2PointRuntime(candidate.ct0[index], `FAME ct0[${index}]`);
    if (pointError !== null) return pointError;
  }

  const msp = candidate.msp;
  if (typeof msp !== 'object' || msp === null) {
    return 'FAME ciphertext MSP must be an object';
  }
  const rows = (msp as Record<string, unknown>).rows;
  if (!Array.isArray(rows) || rows.length !== expectedRows) {
    return `FAME ciphertext MSP must contain exactly ${expectedRows} rows`;
  }
  if (!Array.isArray(candidate.ct) || candidate.ct.length !== rows.length) {
    return 'FAME ciphertext rows must align one-for-one with its MSP rows';
  }
  for (let rowIndex = 0; rowIndex < candidate.ct.length; rowIndex += 1) {
    const triple = candidate.ct[rowIndex];
    if (!Array.isArray(triple) || triple.length !== 3) {
      return `FAME ciphertext row ${rowIndex} must contain exactly three G1 points`;
    }
    for (let columnIndex = 0; columnIndex < triple.length; columnIndex += 1) {
      const pointError = validateG1PointRuntime(
        triple[columnIndex],
        `FAME ct[${rowIndex}][${columnIndex}]`,
      );
      if (pointError !== null) return pointError;
    }
  }
  return validateGtRuntime(candidate.ctPrime, 'FAME ctPrime');
}

function validateHeaderStructure(header: EpochAccessHeader): string | null {
  try {
    assertIdentifier(header.objectId, 'object id');
    assertEpoch(header.epoch);
    const versionError = validateContentVersion(header.contentVersion);
    if (versionError !== null) return versionError;
    if (
      !Number.isSafeInteger(header.revision) ||
      header.revision < 1 ||
      header.revision > 0xffff_ffff
    ) {
      return 'header revision is outside uint32';
    }
    const expectedGated = gatePolicy(header.businessPolicy, header.epoch);
    const expectedMsp = policyToMsp(expectedGated);
    const ciphertextShapeError = validateFameCiphertextShape(
      header.ciphertext,
      expectedMsp.rows.length,
    );
    if (ciphertextShapeError !== null) return ciphertextShapeError;
    if (!bytesEqual(encodePolicy(expectedGated), encodePolicy(header.gatedPolicy))) {
      return 'gated policy is not the declared business policy AND declared epoch';
    }
    if (!bytesEqual(encodePolicy(expectedGated), encodePolicy(header.ciphertext.policy))) {
      return 'FAME ciphertext policy does not match the declared gated policy';
    }
    if (!bytesEqual(encodeMsp(expectedMsp), encodeMsp(header.ciphertext.msp))) {
      return 'FAME ciphertext MSP does not match the declared gated policy';
    }
    if (header.businessExpression !== formatPolicy(header.businessPolicy)) {
      return 'business-policy display string is stale';
    }
    if (header.gatedExpression !== formatPolicy(header.gatedPolicy)) {
      return 'gated-policy display string is stale';
    }
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : 'header validation failed';
  }
}

function checkpointMatches(
  header: EpochAccessHeader,
  checkpoint: TrustedCheckpoint,
): boolean {
  return (
    checkpoint.objectId === header.objectId &&
    checkpoint.epoch === header.epoch &&
    checkpoint.revision === header.revision &&
    bytesEqual(checkpoint.headerDigest, computeAccessHeaderDigest(header))
  );
}

/**
 * Join every independently authenticated part of a source record before an
 * owner capability is allowed to carry its DEK into a new header.
 *
 * A valid checkpoint authenticates one header and a valid owner capsule
 * authenticates one payload, but those facts alone do not say the two belong
 * together.  Without these joins, payload+owner-capsule B could be spliced to
 * header+checkpoint A and inherit A's business policy during rewrap.
 */
function validateSourceRecord(record: RevocableRecord): string | null {
  const { payload, ownerCapsule, currentHeader: header } = record;

  if (
    payload.objectId !== header.objectId ||
    payload.contentVersion !== header.contentVersion
  ) {
    return 'payload and current header identify different objects or content versions';
  }
  if (
    ownerCapsule.objectId !== payload.objectId ||
    ownerCapsule.contentVersion !== payload.contentVersion
  ) {
    return 'owner capsule and payload identify different objects or content versions';
  }
  const expectedPayloadAad = payloadAad(payload.objectId, payload.contentVersion);
  if (!bytesEqual(expectedPayloadAad, payload.aad)) {
    return 'payload metadata does not match its authenticated-data encoding';
  }
  const actualPayloadDigest = computePayloadDigest(payload);
  if (!bytesEqual(actualPayloadDigest, payload.digest)) {
    return 'payload bytes do not match the payload digest';
  }
  if (!bytesEqual(actualPayloadDigest, header.payloadDigest)) {
    return 'current header is bound to a different payload digest';
  }
  if (!bytesEqual(actualPayloadDigest, ownerCapsule.payloadDigest)) {
    return 'owner capsule is bound to a different payload digest';
  }

  const expectedHeaderAad = accessWrapAad(
    header.objectId,
    header.contentVersion,
    actualPayloadDigest,
    header.epoch,
    header.revision,
    header.businessPolicy,
    header.gatedPolicy,
  );
  if (!bytesEqual(expectedHeaderAad, header.wrapAad)) {
    return 'current header metadata does not match its authenticated-data encoding';
  }
  const expectedOwnerAad = ownerAad(
    ownerCapsule.ownerId,
    ownerCapsule.objectId,
    ownerCapsule.contentVersion,
    actualPayloadDigest,
  );
  if (!bytesEqual(expectedOwnerAad, ownerCapsule.aad)) {
    return 'owner-capsule metadata does not match its authenticated-data encoding';
  }
  return null;
}

function asSecretKey(key: AccessKey): SecretKey {
  return 'issued' in key ? key.issued.key : key;
}

async function openPayloadWithDek(
  payload: PayloadCiphertext,
  dek: Uint8Array,
): Promise<{ readonly ok: true; readonly plaintext: string } | OpenFailure> {
  const shapeError = validatePayloadShape(payload);
  if (shapeError !== null) return malformed(shapeError);
  const expectedAad = payloadAad(payload.objectId, payload.contentVersion);
  if (!bytesEqual(expectedAad, payload.aad)) {
    return integrityRejected('payload metadata no longer matches its authenticated-data encoding');
  }
  const opened = await decryptWithRawKey(
    dek,
    payload.nonce,
    expectedAad,
    payload.ciphertext,
  );
  if (opened === null) {
    return tagRejected('payload authentication failed');
  }
  try {
    return {
      ok: true,
      plaintext: decoder.decode(opened),
    };
  } catch {
    return malformed('authenticated payload is not valid UTF-8');
  } finally {
    opened.fill(0);
  }
}

export async function openEpochRecord(
  snapshot: StoredSnapshot,
  key: AccessKey,
  checkpoint: TrustedCheckpoint | null,
): Promise<OpenOutcome> {
  const { payload, accessHeader: header } = snapshot;
  const payloadShapeError = validatePayloadShape(payload);
  if (payloadShapeError !== null) return malformed(payloadShapeError);
  const headerShapeError = validateAccessHeaderShape(header);
  if (headerShapeError !== null) return malformed(headerShapeError);
  if (checkpoint !== null) {
    const checkpointShapeError = validateCheckpointShape(checkpoint);
    if (checkpointShapeError !== null) return malformed(checkpointShapeError);
  }
  if (
    payload.objectId !== header.objectId ||
    payload.contentVersion !== header.contentVersion
  ) {
    return malformed('payload and access header identify different objects or content versions');
  }
  const actualPayloadDigest = computePayloadDigest(payload);
  if (
    !bytesEqual(actualPayloadDigest, payload.digest) ||
    !bytesEqual(actualPayloadDigest, header.payloadDigest)
  ) {
    return integrityRejected('payload bytes do not match the digest bound into the access header');
  }
  const expectedPayloadAad = payloadAad(payload.objectId, payload.contentVersion);
  if (!bytesEqual(expectedPayloadAad, payload.aad)) {
    return integrityRejected(
      'payload metadata no longer matches its authenticated-data encoding',
    );
  }

  if (checkpoint !== null && !checkpointMatches(header, checkpoint)) {
    return {
      ok: false,
      code: 'ROLLBACK_DETECTED',
      detail:
        'the supplied header does not match the separately trusted epoch/revision/header digest',
    };
  }

  const expectedWrapAad = accessWrapAad(
    header.objectId,
    header.contentVersion,
    actualPayloadDigest,
    header.epoch,
    header.revision,
    header.businessPolicy,
    header.gatedPolicy,
  );
  if (!bytesEqual(expectedWrapAad, header.wrapAad)) {
    return integrityRejected(
      'access-header metadata no longer matches its authenticated-data encoding',
    );
  }

  const recovered = decrypt(header.ciphertext, asSecretKey(key));
  if (!recovered.ok) {
    return {
      ok: false,
      code: 'POLICY_UNSATISFIED',
      detail: recovered.detail,
    };
  }

  const accessKek = await deriveAccessKek(recovered.recovered);
  let dek: Uint8Array | null = null;
  try {
    dek = await decryptWithRawKey(
      accessKek,
      header.wrappedDekNonce,
      expectedWrapAad,
      header.wrappedDek,
    );
  } finally {
    accessKek.fill(0);
  }
  if (dek === null) {
    return tagRejected('FAME completed, but the recovered value did not authenticate the DEK capsule');
  }
  try {
    const outcome = await openPayloadWithDek(payload, dek);
    return outcome.ok
      ? {
          ok: true,
          code: 'OPENED',
          plaintext: outcome.plaintext,
          epoch: header.epoch,
          revision: header.revision,
        }
      : outcome;
  } finally {
    dek.fill(0);
  }
}

type OwnerDekOutcome =
  | { readonly ok: true; readonly dek: Uint8Array }
  | {
      readonly ok: false;
      readonly kind: 'malformed' | 'integrity' | 'tag';
      readonly detail: string;
    };

async function unwrapOwnerDek(
  owner: OwnerCapability,
  payload: PayloadCiphertext,
  capsule: OwnerCapsule,
): Promise<OwnerDekOutcome> {
  const payloadShapeError = validatePayloadShape(payload);
  if (payloadShapeError !== null) {
    return { ok: false, kind: 'malformed', detail: payloadShapeError };
  }
  const capsuleShapeError = validateOwnerCapsuleShape(capsule);
  if (capsuleShapeError !== null) {
    return { ok: false, kind: 'malformed', detail: capsuleShapeError };
  }
  if (
    capsule.objectId !== payload.objectId ||
    capsule.contentVersion !== payload.contentVersion
  ) {
    return {
      ok: false,
      kind: 'integrity',
      detail: 'owner capsule and payload identify different objects or content versions',
    };
  }
  const actualDigest = computePayloadDigest(payload);
  if (
    !bytesEqual(actualDigest, payload.digest) ||
    !bytesEqual(actualDigest, capsule.payloadDigest)
  ) {
    return {
      ok: false,
      kind: 'integrity',
      detail: 'payload bytes do not match the digest bound into the owner capsule',
    };
  }
  const expectedAad = ownerAad(
    capsule.ownerId,
    capsule.objectId,
    capsule.contentVersion,
    actualDigest,
  );
  if (!bytesEqual(expectedAad, capsule.aad)) {
    return {
      ok: false,
      kind: 'integrity',
      detail: 'owner-capsule metadata no longer matches its authenticated-data encoding',
    };
  }
  const dek = await decryptWithCryptoKey(
    owner.key,
    capsule.nonce,
    expectedAad,
    capsule.wrappedDek,
  );
  return dek === null
    ? {
        ok: false,
        kind: 'tag',
        detail: 'owner capability or owner capsule failed AES-GCM tag verification',
      }
    : { ok: true, dek };
}

export async function ownerOpenRecord(
  owner: OwnerCapability,
  record: RevocableRecord,
): Promise<OwnerOpenOutcome> {
  const unwrapped = await unwrapOwnerDek(owner, record.payload, record.ownerCapsule);
  if (!unwrapped.ok) {
    if (unwrapped.kind === 'malformed') return malformed(unwrapped.detail);
    return unwrapped.kind === 'tag' ? tagRejected(unwrapped.detail) : integrityRejected(unwrapped.detail);
  }
  const { dek } = unwrapped;
  try {
    const outcome = await openPayloadWithDek(record.payload, dek);
    return outcome.ok
      ? {
          ok: true,
          code: 'OPENED',
          plaintext: outcome.plaintext,
          objectId: record.payload.objectId,
          contentVersion: record.payload.contentVersion,
        }
      : outcome;
  } finally {
    dek.fill(0);
  }
}

/**
 * Demonstrate inherited FAME escrow correctly: msk first mints a satisfying
 * key, then that ordinary key follows the same open path as a holder key.
 */
export async function authorityEscrowOpen(
  system: EpochSystem,
  snapshot: StoredSnapshot,
  checkpoint: TrustedCheckpoint | null,
): Promise<AuthorityEscrowOutcome> {
  const labels = minimalSatisfyingLabels(
    snapshot.accessHeader.ciphertext.policy,
    snapshot.accessHeader.ciphertext.msp,
  );
  system.serial += 1;
  const { key } = keygen(
    system.authority.msk,
    labels,
    system.rng,
    `revocation:authority-escrow:${system.serial}`,
  );
  system.ledger.authorityEscrowKeyGenerations += 1;
  return {
    mintedLabels: labels,
    keyElements: 3 + 3 * key.sk.size + 3,
    open: await openEpochRecord(snapshot, key, checkpoint),
  };
}

/* -------------------------------------------------------------------------- */
/* Owner-assisted header update                                               */
/* -------------------------------------------------------------------------- */

export async function rewrapEpochRecord(
  system: EpochSystem,
  owner: OwnerCapability,
  record: RevocableRecord,
): Promise<RewrapOutcome> {
  const payloadShapeError = validatePayloadShape(record.payload);
  if (payloadShapeError !== null) {
    return { ok: false, code: 'SOURCE_RECORD_REJECTED', detail: payloadShapeError };
  }
  const headerShapeError = validateAccessHeaderShape(record.currentHeader);
  if (headerShapeError !== null) {
    return { ok: false, code: 'SOURCE_RECORD_REJECTED', detail: headerShapeError };
  }
  const ownerShapeError = validateOwnerCapsuleShape(record.ownerCapsule);
  if (ownerShapeError !== null) {
    return { ok: false, code: 'OWNER_CAPSULE_REJECTED', detail: ownerShapeError };
  }
  const checkpointShapeError = validateCheckpointShape(record.checkpoint);
  if (checkpointShapeError !== null) {
    return {
      ok: false,
      code: 'SOURCE_CHECKPOINT_REJECTED',
      detail: checkpointShapeError,
    };
  }
  const sourceError = validateSourceRecord(record);
  if (sourceError !== null) {
    return {
      ok: false,
      code: 'SOURCE_RECORD_REJECTED',
      detail: sourceError,
    };
  }
  if (!checkpointMatches(record.currentHeader, record.checkpoint)) {
    return {
      ok: false,
      code: 'SOURCE_CHECKPOINT_REJECTED',
      detail: 'the owner refused to update a record whose current header is not its trusted revision',
    };
  }
  if (system.currentEpoch <= record.currentHeader.epoch) {
    return {
      ok: false,
      code: 'EPOCH_NOT_ADVANCED',
      detail: `current epoch ${system.currentEpoch} is not newer than header epoch ${record.currentHeader.epoch}`,
    };
  }

  const unwrapped = await unwrapOwnerDek(owner, record.payload, record.ownerCapsule);
  if (!unwrapped.ok) {
    return {
      ok: false,
      code: 'OWNER_CAPSULE_REJECTED',
      detail: unwrapped.detail,
    };
  }
  const { dek } = unwrapped;

  try {
    const currentHeader = await makeAccessHeader(
      system,
      record.payload.objectId,
      record.payload.contentVersion,
      record.payload.digest,
      record.currentHeader.businessPolicy,
      system.currentEpoch,
      record.currentHeader.revision + 1,
      dek,
    );
    const checkpoint = makeCheckpoint(currentHeader);
    const headerBytes = encodeAccessHeader(currentHeader).length;
    const next: RevocableRecord = {
      payload: record.payload,
      ownerCapsule: record.ownerCapsule,
      currentHeader,
      checkpoint,
    };
    const work: RewrapWork = {
      ownerDekUnwraps: 1,
      fameHeaderEncryptions: 1,
      accessDekWraps: 1,
      accessHeaderBytesWritten: headerBytes,
      checkpointWrites: 1,
      payloadEncryptions: 0,
      payloadBytesRewritten: 0,
    };

    system.ledger.ownerDekUnwrapsForRewrap += 1;
    system.ledger.fameHeaderEncryptions += 1;
    system.ledger.accessDekWraps += 1;
    system.ledger.accessHeaderBytesWritten += headerBytes;
    system.ledger.checkpointWrites += 1;
    system.ledger.rewrapOperations += 1;
    // Deliberately no write to rewrapPayloadBytesWritten.

    return {
      ok: true,
      record: next,
      fromEpoch: record.currentHeader.epoch,
      toEpoch: currentHeader.epoch,
      work,
    };
  } finally {
    dek.fill(0);
  }
}
