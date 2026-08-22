/**
 * The lab's model layer: an authority, a staff list, a registry, and an
 * envelope sealed under a policy.
 *
 * Everything here composes the pieces in src/fame; nothing here is new
 * cryptography. It exists so the UI never reaches into the scheme directly and
 * so the whole set of exhibits -- issue, decrypt, threshold, collude, escrow,
 * revoke -- can be driven from tests without a browser.
 *
 * All key material is per-session and in memory. Nothing is persisted.
 */
import {
  GT_ONE,
  gtEquals,
  gtToHex,
  pairingCount,
  resetPairingCount,
  type GTElement,
} from './bls';
import { FAILURE_CODES, SUCCESS_CODE, type FailureCodeId } from './codes';
import {
  analyseCollusion,
  poolKeys,
  type CollusionAnalysis,
  type PooledKey,
} from './collusion';
import {
  decrypt,
  encrypt,
  keygen,
  randomGT,
  setup,
  type Authority,
  type Ciphertext,
  type CiphertextWitness,
  type IssuedKey,
  type KeyWitness,
  type SecretKey,
} from './fame';
import { openRecord, sealRecord, toHex, type SealedRecord } from './kem';
import {
  minimalSatisfyingLabels,
  policyToMsp,
  reconstruct,
  type Msp,
  type Reconstruction,
} from './msp';
import { AttributeRegistry, type RegistryGrowth } from './oneuse';
import { formatPolicy, type PolicyNode } from './policy';
import { secureRandom, type RandomSource } from './rand';

export interface Person {
  readonly name: string;
  /** Attribute names as a human writes them, before indexing. */
  readonly attributes: readonly string[];
  /** Struck off the authority's list. Changes nothing about the key. */
  revoked: boolean;
}

export interface KeyRecord {
  readonly holder: string;
  readonly issued: IssuedKey;
  /** Registry k for each held attribute at the moment of issue. */
  readonly copiesAtIssue: ReadonlyMap<string, number>;
  /** Total group elements in the key: 3 (sk0) + 3 per label + 3 (sk'). */
  readonly elements: number;
  /** Monotonic issue counter, so the UI can show which key is newer. */
  readonly serial: number;
}

export interface Envelope {
  readonly serial: number;
  readonly policy: PolicyNode;
  readonly expression: string;
  readonly msp: Msp;
  readonly ciphertext: Ciphertext;
  readonly witness: CiphertextWitness;
  readonly sealed: SealedRecord;
  /** The plaintext, kept so the page can prove an opened record is the right one. */
  readonly plaintext: string;
}

export type AttemptOutcome = 'opened' | 'denied' | 'blocked';

export interface Attempt {
  readonly who: string;
  readonly outcome: AttemptOutcome;
  /** The exported code id, printed verbatim by the UI. */
  readonly code: string;
  readonly headline: string;
  readonly detail: string;
  readonly reconstruction: Reconstruction;
  /** Rows the key could not satisfy, in row order. */
  readonly unsatisfiedRows: readonly number[];
  /** What FAME's Decrypt produced, when it ran at all. */
  readonly recovered: GTElement | null;
  /** Did it equal the encapsulated element, byte for byte? */
  readonly recoveredMatches: boolean;
  /** The AEAD's answer, which is what actually gates the record. */
  readonly aeadAccepted: boolean;
  readonly plaintext: string | null;
  /**
   * Pairings this attempt actually computed.
   *
   * Six when decryption runs, whatever the policy looks like -- that constant
   * is FAME's headline result, and counting is how the page shows it instead
   * of quoting a millisecond figure that describes the reader's laptop.
   */
  readonly pairings: number;
}

/* -------------------------------------------------------------------------- */
/* Authority and issuance                                                     */
/* -------------------------------------------------------------------------- */

export interface LabState {
  readonly authority: Authority;
  readonly registry: AttributeRegistry;
  readonly people: Person[];
  readonly keys: Map<string, KeyRecord>;
  readonly witnesses: Map<string, KeyWitness>;
  serial: number;
  readonly rng: RandomSource;
}

/** The cast the brief names, plus Eve, who exists only to collude with Bob. */
export const DEFAULT_PEOPLE: readonly { name: string; attributes: string[] }[] = [
  { name: 'Alice', attributes: ['Doctor', 'Cardiology'] },
  { name: 'Bob', attributes: ['Doctor'] },
  { name: 'Carol', attributes: ['Emergency'] },
  { name: 'Dan', attributes: ['Nurse'] },
  { name: 'Eve', attributes: ['Cardiology'] },
];

/** Attributes the policy builder offers. Large-universe: any string would work. */
export const ATTRIBUTE_UNIVERSE: readonly string[] = [
  'Doctor',
  'Cardiology',
  'Emergency',
  'Nurse',
  'OnCall',
  'Research',
];

export function createLab(rng: RandomSource = secureRandom): LabState {
  return {
    authority: setup(rng),
    registry: new AttributeRegistry(),
    people: DEFAULT_PEOPLE.map((p) => ({ ...p, attributes: [...p.attributes], revoked: false })),
    keys: new Map(),
    witnesses: new Map(),
    serial: 0,
    rng,
  };
}

/**
 * Mint a key for one person at the registry's current k.
 *
 * Issuing expands every held attribute into all of its indexed copies. That is
 * the second half of the one-use transform, and skipping it is how a
 * policy-side-only implementation fails: the key would carry `Doctor:1` and
 * the ciphertext would ask for `Doctor:2`.
 */
export function issueKey(state: LabState, person: Person): KeyRecord {
  const labels = state.registry.expand(person.attributes);
  state.serial += 1;
  const { key, witness } = keygen(
    state.authority.msk,
    labels,
    state.rng,
    `${person.name}#${state.serial}`,
  );
  const issued: IssuedKey = {
    holder: person.name,
    heldNames: [...person.attributes],
    key,
    witness,
    copiesAtIssue: new Map(person.attributes.map((n) => [n, state.registry.copies(n)])),
  };
  const record: KeyRecord = {
    holder: person.name,
    issued,
    copiesAtIssue: issued.copiesAtIssue,
    elements: 3 + 3 * key.sk.size + 3,
    serial: state.serial,
  };
  state.keys.set(person.name, record);
  state.witnesses.set(person.name, witness);
  return record;
}

export function issueAll(state: LabState): KeyRecord[] {
  return state.people.map((p) => issueKey(state, p));
}

/**
 * A key is stale when the registry has since raised k for one of its attributes.
 *
 * FAME fixes k at set-up. Because the scheme is large-universe, raising it
 * later costs nothing in the public key -- it invalidates the keys already
 * issued. The page shows that rather than hiding it behind a silent re-issue.
 */
export function staleAttributes(state: LabState, record: KeyRecord): string[] {
  return record.issued.heldNames.filter(
    (n) => state.registry.copies(n) > (record.copiesAtIssue.get(n) ?? 1),
  );
}

/** Register a policy's attribute demands and report which k values moved. */
export function observePolicy(state: LabState, policy: PolicyNode): RegistryGrowth[] {
  return state.registry.observePolicy(policy);
}

/* -------------------------------------------------------------------------- */
/* Sealing                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Encapsulate a fresh GT element under the policy, then AES-256-GCM the record
 * under a key derived from it.
 *
 * The record is NOT ABE-encrypted, and the split is the point: FAME's message
 * space is a single GT element, so anything of application size goes through
 * the KEM. The policy string is the AEAD's associated data.
 */
export async function sealUnder(
  state: LabState,
  policy: PolicyNode,
  plaintext: string,
): Promise<Envelope> {
  const msp = policyToMsp(policy);
  state.serial += 1;
  const serial = state.serial;
  const { element } = randomGT(state.rng, `envelope#${serial}`);
  const { ciphertext, witness } = encrypt(
    state.authority.pk,
    policy,
    msp,
    element,
    state.rng,
    `envelope#${serial}`,
  );
  const expression = formatPolicy(policy);
  const sealed = await sealRecord(element, plaintext, expression, state.rng, `gcm#${serial}`);
  return { serial, policy, expression, msp, ciphertext, witness, sealed, plaintext };
}

/* -------------------------------------------------------------------------- */
/* Attempts                                                                   */
/* -------------------------------------------------------------------------- */

async function runAttempt(
  who: string,
  envelope: Envelope,
  key: SecretKey,
  pooled: boolean,
): Promise<Attempt> {
  resetPairingCount();
  const result = decrypt(envelope.ciphertext, key);
  const pairings = pairingCount();

  if (!result.ok) {
    const code: FailureCodeId = 'POLICY_UNSATISFIED';
    return {
      who,
      outcome: 'denied',
      code: FAILURE_CODES[code].id,
      headline: FAILURE_CODES[code].title,
      detail: result.detail,
      reconstruction: result.reconstruction,
      unsatisfiedRows: result.unsatisfiedRows,
      recovered: null,
      recoveredMatches: false,
      aeadAccepted: false,
      plaintext: null,
      pairings,
    };
  }

  const matches = gtEquals(result.recovered, envelope.witness.encapsulated);
  const opened = await openRecord(result.recovered, envelope.sealed);

  if (opened.ok) {
    return {
      who,
      outcome: 'opened',
      code: SUCCESS_CODE.id,
      headline: SUCCESS_CODE.title,
      detail:
        'Decrypt returned the encapsulated GT element exactly; HKDF-SHA-256 derived the same AES-256 key and GCM verified the tag.',
      reconstruction: result.reconstruction,
      unsatisfiedRows: [],
      recovered: result.recovered,
      recoveredMatches: matches,
      aeadAccepted: true,
      plaintext: opened.plaintext,
      pairings,
    };
  }

  // The policy was satisfied, decryption ran, and the AEAD still refused. With
  // a spliced key that is collusion resistance; with a coherent key it would
  // mean the key came from a different authority.
  const code: FailureCodeId = 'COLLUSION_BLOCKED';
  return {
    who,
    outcome: 'blocked',
    code: pooled ? FAILURE_CODES[code].id : 'AEAD_TAG_REJECTED',
    headline: pooled ? FAILURE_CODES[code].title : 'Wrong key material',
    detail: pooled
      ? 'The pooled attributes satisfied the policy and Decrypt ran to completion. Nothing checked for collusion -- the group element it returned was simply not the one encapsulated, so AES-GCM rejected the tag.'
      : 'Decrypt ran but returned a different GT element, so the derived AES key was wrong and GCM rejected the tag.',
    reconstruction: result.reconstruction,
    unsatisfiedRows: [],
    recovered: result.recovered,
    recoveredMatches: matches,
    aeadAccepted: false,
    plaintext: null,
    pairings,
  };
}

/** One person tries to open the envelope with their own key. */
export function attemptOpen(envelope: Envelope, record: KeyRecord): Promise<Attempt> {
  return runAttempt(record.holder, envelope, record.issued.key, false);
}

export interface CollusionOutcome {
  readonly attempt: Attempt;
  readonly analysis: CollusionAnalysis;
  readonly pooled: PooledKey;
}

/**
 * Two people pool their key material and try both splice directions.
 *
 * Returns both attempts. Reporting only the one that fails most tidily would
 * be picking the evidence.
 */
export async function attemptCollusion(
  state: LabState,
  envelope: Envelope,
  a: KeyRecord,
  b: KeyRecord,
): Promise<CollusionOutcome[]> {
  const witnesses = new Map(state.witnesses);
  const out: CollusionOutcome[] = [];
  for (const [base, other] of [
    [a, b],
    [b, a],
  ] as const) {
    const pooled = poolKeys(base.issued, other.issued);
    const analysis = analyseCollusion(envelope.ciphertext, pooled, witnesses, envelope.witness);
    const attempt = await runAttempt(
      `${base.holder} + ${other.holder}`,
      envelope,
      pooled.key,
      true,
    );
    out.push({ attempt, analysis, pooled });
  }
  return out;
}

export interface EscrowOutcome {
  /** Step 1: the attribute set the authority chose to mint for itself. */
  readonly mintedLabels: readonly string[];
  readonly keyElements: number;
  /** Step 2: that key, used like any other key. */
  readonly attempt: Attempt;
}

/**
 * The escrow property, as two separate steps.
 *
 * msk is not a decryption key. There is no function that takes msk and a
 * ciphertext and returns a plaintext. What msk grants is KeyGen for an
 * arbitrary attribute set -- so the authority mints itself a key that satisfies
 * the policy, and then decrypts with it exactly like everybody else.
 * Collapsing the two steps into "the authority can decrypt everything" reaches
 * the right conclusion by the wrong route.
 */
export async function escrowOpen(state: LabState, envelope: Envelope): Promise<EscrowOutcome> {
  const mintedLabels = minimalSatisfyingLabels(envelope.policy, envelope.msp);
  state.serial += 1;
  const { key } = keygen(
    state.authority.msk,
    mintedLabels,
    state.rng,
    `authority#${state.serial}`,
  );
  const attempt = await runAttempt('Authority', envelope, key, false);
  return { mintedLabels, keyElements: 3 + 3 * key.sk.size + 3, attempt };
}

/* -------------------------------------------------------------------------- */
/* Reporting helpers the UI and the claims suite share                        */
/* -------------------------------------------------------------------------- */

/** Which rows a key satisfies, for highlighting the matrix. */
export function rowCoverage(envelope: Envelope, record: KeyRecord): Map<number, boolean> {
  const held = new Set(record.issued.key.labels);
  return new Map(envelope.msp.rows.map((r) => [r.index, held.has(r.label)]));
}

/** The reconstruction a key would use, without decrypting. */
export function previewReconstruction(envelope: Envelope, labels: readonly string[]): Reconstruction {
  return reconstruct(envelope.policy, envelope.msp, new Set(labels));
}

export function fingerprint(x: GTElement | null): string {
  if (x === null) return '--';
  const hex = gtToHex(x);
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

export function isIdentity(x: GTElement | null): boolean {
  return x !== null && gtEquals(x, GT_ONE);
}

export function sealedFingerprint(e: Envelope): string {
  const hex = toHex(e.sealed.ciphertext);
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}
