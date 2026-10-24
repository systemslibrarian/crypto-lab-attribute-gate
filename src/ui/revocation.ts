/**
 * Learner-facing bounded epoch-gating and owner-assisted rewrap lesson.
 *
 * This panel executes one complete lifecycle around the existing FAME model.
 * It is intentionally labelled as an application-layer adaptation: it is not
 * RW15, revocable ABE, public ciphertext update, or a proved composition.
 */
import { attr } from '../fame/policy';
import {
  advanceEpoch,
  authorityEscrowOpen,
  computeAccessHeaderDigest,
  computePayloadDigest,
  costSnapshot,
  createEpochSystem,
  createOwnerCapability,
  encodeAccessHeader,
  encodePayloadCiphertext,
  epochAttribute,
  issueCurrentEpochKey,
  openEpochRecord,
  ownerOpenRecord,
  rewrapEpochRecord,
  revokeHolder,
  sealEpochRecord,
  takeStorageSnapshot,
  type CostLedger,
  type EpochKeyRecord,
  type IssueResult,
  type OpenOutcome,
  type OwnerOpenOutcome,
  type RewrapWork,
} from '../revocation';
import {
  button,
  clear,
  disclosure,
  el,
  liveRegion,
  scroller,
  section,
  shortHex,
  statusChip,
  type Child,
} from './dom';

const OBJECT_ID = 'case-record-0317';
const RECORD = 'CASE-0317: retained teaching record';
const OWNER_ID = 'Records owner';
const ALICE = { id: 'Alice', attributes: ['Doctor'] } as const;
const BOB = { id: 'Bob', attributes: ['Doctor'] } as const;

type VerdictTone = 'pass' | 'fail' | 'warn' | 'neutral';

function codeTag(code: string): HTMLElement {
  return el('span', { class: 'code-tag', text: code });
}

function outcomeBox(
  tone: VerdictTone,
  headline: string,
  code: string,
  detail: string,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElement {
  const outcome = tone === 'pass' ? 'opened' : tone === 'warn' ? 'blocked' : tone === 'neutral' ? 'info' : 'failed';
  const verdictClass = tone === 'pass' ? 'verdict-pass' : tone === 'warn' ? 'verdict-warn' : tone === 'fail' ? 'verdict-fail' : '';
  return el(
    'article',
    {
      class: `verdict ${verdictClass}`.trim(),
      attrs: { 'data-outcome': outcome, 'data-code': code, ...attrs },
    },
    el('div', { class: 'verdict-head' }, statusChip(tone, headline), codeTag(code)),
    el('p', { class: 'verdict-detail', text: detail }),
    ...children,
  );
}

function facts(entries: readonly Child[]): HTMLUListElement {
  return el(
    'ul',
    { class: 'honesty-list' },
    ...entries.map((entry) => el('li', {}, entry)),
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function digestRef(bytes: Uint8Array): HTMLElement {
  return el('code', { text: shortHex(hex(bytes), 16, 12) });
}

function requireIssued(result: IssueResult, label: string): EpochKeyRecord {
  if (!result.ok) throw new Error(`${label}: expected a key, received ${result.code}`);
  return result.key;
}

function outcomeCode(result: OpenOutcome): string {
  return result.ok ? result.code : result.code;
}

function openFact(result: OpenOutcome): Child {
  return result.ok
    ? el(
        'span',
        {},
        'Authenticated plaintext: ',
        el('code', { text: result.plaintext }),
        `; header epoch ${result.epoch}, revision ${result.revision}.`,
      )
    : el('span', {}, 'Failure detail: ', result.detail);
}

const LEDGER_LABELS: ReadonlyArray<readonly [keyof CostLedger, string]> = [
  ['epochAdvances', 'Epoch advances'],
  ['revocations', 'Revocation-list additions'],
  ['holderKeyGenerations', 'Complete holder FAME key generations'],
  ['authorityEscrowKeyGenerations', 'Authority escrow key generations'],
  ['fameHeaderEncryptions', 'FAME access-header encryptions'],
  ['payloadAeadEncryptions', 'Payload AEAD encryptions'],
  ['payloadPlaintextBytesEncrypted', 'Payload plaintext bytes encrypted'],
  ['ownerCapsuleEncryptions', 'Owner recovery-capsule encryptions'],
  ['ownerDekUnwrapsForRewrap', 'Owner DEK unwraps for rewrap'],
  ['accessDekWraps', 'Access DEK wraps'],
  ['accessHeaderBytesWritten', 'Access-header bytes written'],
  ['checkpointWrites', 'Trusted checkpoint writes'],
  ['rewrapOperations', 'Completed rewrap operations'],
  ['rewrapPayloadBytesWritten', 'Payload bytes rewritten during rewrap'],
];

/** A self-contained view; App appends `element` and awaits `initialize()`. */
export class EpochRevocationLesson {
  readonly element: HTMLElement;

  private readonly resultHost: HTMLElement;
  private readonly runButton: HTMLButtonElement;
  private initialized = false;
  private busy = false;

  constructor() {
    this.resultHost = liveRegion('Epoch revocation lifecycle results');
    this.resultHost.setAttribute('data-host', 'epoch-revocation-result');

    this.runButton = button(
      'Run the complete epoch lifecycle',
      () => void this.runLifecycle().catch((error: unknown) => this.renderUnexpected(error)),
      'btn btn-primary',
    );
    this.runButton.id = 'epoch-revocation-run';
    this.runButton.setAttribute('data-revocation-action', 'run-lifecycle');

    this.element = section(
      {
        id: 'epoch-revocation',
        number: '11',
        title: 'Advance an epoch and account for revocation work',
        lede:
          'This bounded application-layer FAME adaptation withholds a complete new key from a revoked holder and lets an escrowed owner replace selected access headers. One run tests current and retained snapshots, trusted-checkpoint rollback detection, byte-level payload preservation, measured costs, and both remaining escrow powers.',
      },
      outcomeBox(
        'warn',
        'Scope boundary',
        'APPLICATION_LAYER_FAME_ADAPTATION',
        'This is not RW15, not a revocable-ABE or revocable-storage-ABE construction, not public ciphertext update, and not a FAME/RW15/revocation theorem. Rewrap requires owner-secret DEK recovery.',
        { 'data-revocation-scope': 'application-layer-fame-adaptation' },
      ),
      el(
        'p',
        {},
        'The business rule is ',
        el('code', { text: 'Doctor' }),
        '. The live model gates it as ',
        el('code', { text: `Doctor AND ${epochAttribute(1)}` }),
        ', then advances to ',
        el('code', { text: `Doctor AND ${epochAttribute(2)}` }),
        '. Alice receives a newly randomized complete epoch-2 FAME key; Bob is revoked and receives none.',
      ),
      this.runButton,
      this.resultHost,
      this.scopeDisclosure(),
    );

    this.runButton.disabled = true;
    this.element.setAttribute('aria-busy', 'true');
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    this.runButton.disabled = false;
    this.element.removeAttribute('aria-busy');
    this.element.setAttribute('data-revocation-ready', 'true');
  }

  private async runLifecycle(): Promise<void> {
    if (!this.initialized || this.busy) return;
    this.busy = true;
    this.runButton.disabled = true;
    this.element.setAttribute('aria-busy', 'true');
    clear(this.resultHost);
    this.resultHost.appendChild(statusChip('neutral', 'Running real FAME, HKDF, and AES-GCM operations'));

    try {
      const system = createEpochSystem();
      const owner = await createOwnerCapability(OWNER_ID);
      const policy = attr('Doctor', 'epoch-lesson-doctor');

      const epoch1Record = await sealEpochRecord(system, owner, OBJECT_ID, policy, RECORD);
      const oldSnapshot = takeStorageSnapshot(epoch1Record);
      const aliceEpoch1 = requireIssued(
        issueCurrentEpochKey(system, ALICE),
        'Alice epoch 1 issuance',
      );
      const bobEpoch1 = requireIssued(
        issueCurrentEpochKey(system, BOB),
        'Bob epoch 1 issuance',
      );

      revokeHolder(system, BOB.id);
      const transition = advanceEpoch(system);
      const rewrap = await rewrapEpochRecord(system, owner, epoch1Record);
      if (!rewrap.ok) throw new Error(`epoch rewrap failed: ${rewrap.code}: ${rewrap.detail}`);
      const epoch2Record = rewrap.record;
      const currentSnapshot = takeStorageSnapshot(epoch2Record);
      const aliceEpoch2 = requireIssued(
        issueCurrentEpochKey(system, ALICE),
        'Alice epoch 2 issuance',
      );
      const bobEpoch2 = issueCurrentEpochKey(system, BOB);

      const bobOld = await openEpochRecord(oldSnapshot, bobEpoch1, epoch1Record.checkpoint);
      const bobCurrent = await openEpochRecord(
        currentSnapshot,
        bobEpoch1,
        epoch2Record.checkpoint,
      );
      const aliceCurrent = await openEpochRecord(
        currentSnapshot,
        aliceEpoch2,
        epoch2Record.checkpoint,
      );
      const savedWithoutCheckpoint = await openEpochRecord(oldSnapshot, bobEpoch1, null);
      const rollbackAgainstCurrent = await openEpochRecord(
        oldSnapshot,
        bobEpoch1,
        epoch2Record.checkpoint,
      );

      const oldPayloadBytes = encodePayloadCiphertext(epoch1Record.payload);
      const currentPayloadBytes = encodePayloadCiphertext(epoch2Record.payload);
      const oldHeaderBytes = encodeAccessHeader(epoch1Record.currentHeader);
      const currentHeaderBytes = encodeAccessHeader(epoch2Record.currentHeader);
      const payloadIdentical = bytesEqual(oldPayloadBytes, currentPayloadBytes);
      const headerChanged = !bytesEqual(oldHeaderBytes, currentHeaderBytes);

      const ownerEscrow = await ownerOpenRecord(owner, epoch2Record);
      const authorityEscrow = await authorityEscrowOpen(
        system,
        currentSnapshot,
        epoch2Record.checkpoint,
      );
      const ledger = costSnapshot(system);

      clear(this.resultHost);
      this.resultHost.append(
        this.bobOldCard(bobOld, bobEpoch1),
        this.bobCurrentCard(bobCurrent, bobEpoch2, transition.to),
        this.aliceCurrentCard(aliceCurrent, aliceEpoch1, aliceEpoch2),
        this.savedSnapshotCard(savedWithoutCheckpoint),
        this.rollbackCard(rollbackAgainstCurrent),
        this.byteComparisonCard(
          payloadIdentical,
          headerChanged,
          oldPayloadBytes.length,
          oldHeaderBytes.length,
          currentHeaderBytes.length,
          epoch1Record,
          epoch2Record,
          rewrap.work,
        ),
        this.escrowCard(ownerEscrow, authorityEscrow),
        this.ledgerCard(ledger),
      );
    } finally {
      this.busy = false;
      this.runButton.disabled = false;
      this.element.removeAttribute('aria-busy');
    }
  }

  private bobOldCard(result: OpenOutcome, key: EpochKeyRecord): HTMLElement {
    const opened = result.ok;
    return outcomeBox(
      opened ? 'warn' : 'fail',
      opened ? 'Bob’s retained epoch-1 material still opens' : 'Bob’s old snapshot did not open',
      outcomeCode(result),
      opened
        ? 'Revoking Bob cannot erase his saved complete key or the authentic epoch-1 header. This is the retained-copy boundary, not a revocation success.'
        : 'The executable old-key/old-snapshot case did not produce the expected retained access.',
      {
        'data-revocation-case': 'bob-old',
        'data-epoch': '1',
        'data-opened': String(opened),
        'data-checkpoint': 'epoch-1',
      },
      facts([
        el('span', {}, 'Held labels: ', el('code', { text: key.issued.key.labels.join(', ') }), '.'),
        el('span', {}, `Complete FAME key elements: ${key.elements}.`),
        openFact(result),
      ]),
    );
  }

  private bobCurrentCard(
    result: OpenOutcome,
    epoch2Issue: IssueResult,
    currentEpoch: number,
  ): HTMLElement {
    const rejected = !result.ok && result.code === 'POLICY_UNSATISFIED';
    const withheld = !epoch2Issue.ok && epoch2Issue.code === 'HOLDER_REVOKED';
    const passed = rejected && withheld;
    return outcomeBox(
      passed ? 'pass' : 'fail',
      passed ? 'Bob cannot open the epoch-2 header' : 'Bob’s current-epoch boundary failed',
      rejected ? result.code : outcomeCode(result),
      passed
        ? 'Bob’s epoch-1 key lacks the new epoch row, and the issuer withholds an entire new randomized FAME key after consulting the application revocation list.'
        : 'The live open or issuance result differed from the expected epoch-gating boundary.',
      {
        'data-revocation-case': 'bob-current',
        'data-epoch': String(currentEpoch),
        'data-opened': String(result.ok),
        'data-key-issued': String(epoch2Issue.ok),
        'data-checkpoint': 'current',
      },
      facts([
        el('span', {}, 'Open result: ', codeTag(outcomeCode(result)), '.'),
        epoch2Issue.ok
          ? el('span', { text: 'Unexpectedly issued Bob a current complete key.' })
          : el('span', {}, 'Issuance result: ', codeTag(epoch2Issue.code), '; ', epoch2Issue.detail, '.'),
      ]),
    );
  }

  private aliceCurrentCard(
    result: OpenOutcome,
    oldKey: EpochKeyRecord,
    currentKey: EpochKeyRecord,
  ): HTMLElement {
    const opened = result.ok;
    return outcomeBox(
      opened ? 'pass' : 'fail',
      opened ? 'Alice’s complete epoch-2 key opens' : 'Alice’s current key failed',
      outcomeCode(result),
      opened
        ? 'The active holder receives a fresh complete FAME key carrying the business label and Access epoch 2; this is not an independently updateable epoch component.'
        : 'The live active-holder path did not authenticate the current record.',
      {
        'data-revocation-case': 'alice-current',
        'data-epoch': '2',
        'data-opened': String(opened),
        'data-checkpoint': 'current',
      },
      facts([
        el('span', {}, 'Old labels: ', el('code', { text: oldKey.issued.key.labels.join(', ') }), '.'),
        el('span', {}, 'New labels: ', el('code', { text: currentKey.issued.key.labels.join(', ') }), '.'),
        el('span', {}, `Old/new complete key sizes: ${oldKey.elements}/${currentKey.elements} group elements.`),
        openFact(result),
      ]),
    );
  }

  private savedSnapshotCard(result: OpenOutcome): HTMLElement {
    const opened = result.ok;
    return outcomeBox(
      opened ? 'warn' : 'fail',
      opened ? 'Saved old snapshot opens without a freshness checkpoint' : 'Saved snapshot result differed',
      outcomeCode(result),
      opened
        ? 'AES-GCM authenticates the old bytes, but authenticity does not say they are current. With no external checkpoint, the old header is still a valid epoch-1 header.'
        : 'The retained old snapshot unexpectedly failed without a checkpoint.',
      {
        'data-revocation-case': 'rollback-no-checkpoint',
        'data-opened': String(opened),
        'data-checkpoint': 'none',
      },
      openFact(result),
    );
  }

  private rollbackCard(result: OpenOutcome): HTMLElement {
    const rejected = !result.ok && result.code === 'ROLLBACK_DETECTED';
    return outcomeBox(
      rejected ? 'pass' : 'fail',
      rejected ? 'Current trusted checkpoint rejects rollback' : 'Rollback was not detected',
      outcomeCode(result),
      rejected
        ? 'The separately retained epoch-2 checkpoint binds object id, epoch, revision, and the digest of the complete current access header. It rejects the authentic but stale epoch-1 header before decryption.'
        : 'The old snapshot did not produce the required rollback rejection against current trusted state.',
      {
        'data-revocation-case': 'rollback-with-checkpoint',
        'data-opened': String(result.ok),
        'data-checkpoint': 'current',
      },
      openFact(result),
    );
  }

  private byteComparisonCard(
    payloadIdentical: boolean,
    headerChanged: boolean,
    payloadBytes: number,
    oldHeaderBytes: number,
    currentHeaderBytes: number,
    oldRecord: Parameters<typeof takeStorageSnapshot>[0],
    currentRecord: Parameters<typeof takeStorageSnapshot>[0],
    work: RewrapWork,
  ): HTMLElement {
    const passed = payloadIdentical && headerChanged && work.payloadBytesRewritten === 0;
    const oldPayloadDigest = computePayloadDigest(oldRecord.payload);
    const newPayloadDigest = computePayloadDigest(currentRecord.payload);
    const oldHeaderDigest = computeAccessHeaderDigest(oldRecord.currentHeader);
    const newHeaderDigest = computeAccessHeaderDigest(currentRecord.currentHeader);
    return outcomeBox(
      passed ? 'pass' : 'fail',
      passed ? 'Payload bytes identical; access header replaced' : 'Byte-level rewrap invariant failed',
      passed ? 'HEADER_REWRAPPED_PAYLOAD_UNCHANGED' : 'REWRAP_BYTE_MISMATCH',
      passed
        ? 'The same serialized AES-GCM payload remains in storage. Owner-assisted rewrap writes a new FAME capsule, wrapped-DEK header, and trusted checkpoint only.'
        : 'The serialized payload changed, the header did not change, or the work ledger claimed payload rewriting.',
      {
        'data-revocation-case': 'payload-header',
        'data-payload-identical': String(payloadIdentical),
        'data-header-changed': String(headerChanged),
        'data-payload-bytes-rewritten': String(work.payloadBytesRewritten),
      },
      facts([
        el(
          'span',
          {},
          `Serialized payload: ${payloadBytes} bytes before and after; SHA-256 `,
          digestRef(oldPayloadDigest),
          ' / ',
          digestRef(newPayloadDigest),
          '.',
        ),
        el(
          'span',
          {},
          `Serialized access header: ${oldHeaderBytes} bytes at epoch 1, ${currentHeaderBytes} bytes at epoch 2; SHA-256 `,
          digestRef(oldHeaderDigest),
          ' / ',
          digestRef(newHeaderDigest),
          '.',
        ),
        el(
          'span',
          {},
          `This rewrap: ${work.ownerDekUnwraps} owner DEK unwrap, ${work.fameHeaderEncryptions} FAME header encryption, ${work.accessDekWraps} DEK wrap, ${work.accessHeaderBytesWritten} header bytes written, ${work.checkpointWrites} checkpoint write, ${work.payloadEncryptions} payload encryption, ${work.payloadBytesRewritten} payload bytes rewritten.`,
        ),
      ]),
    );
  }

  private escrowCard(
    ownerResult: OwnerOpenOutcome,
    authorityResult: Awaited<ReturnType<typeof authorityEscrowOpen>>,
  ): HTMLElement {
    const ownerOpened = ownerResult.ok;
    const authorityOpened = authorityResult.open.ok;
    const expected = ownerOpened && authorityOpened;
    return outcomeBox(
      expected ? 'warn' : 'fail',
      expected ? 'Both modeled escrow powers can recover the record' : 'Escrow demonstration failed',
      expected ? 'OWNER_AND_AUTHORITY_ESCROW' : 'ESCROW_FIXTURE_FAILED',
      expected
        ? 'The owner capability unwraps the DEK recovery capsule directly. Separately, the inherited single-authority FAME master secret mints a satisfying current key and follows the ordinary open path.'
        : 'One or both executable escrow paths did not open the current record.',
      { 'data-revocation-case': 'escrow' },
      facts([
        el(
          'span',
          {
            attrs: {
              'data-revocation-escrow': 'owner',
              'data-opened': String(ownerOpened),
            },
          },
          'Owner capability: ',
          statusChip(ownerOpened ? 'warn' : 'fail', ownerOpened ? 'opens this record through its DEK capsule' : 'did not open'),
          '.',
        ),
        el(
          'span',
          {
            attrs: {
              'data-revocation-escrow': 'authority',
              'data-opened': String(authorityOpened),
            },
          },
          'FAME authority: minted ',
          el('code', { text: authorityResult.mintedLabels.join(', ') }),
          ` (${authorityResult.keyElements} group elements); `,
          statusChip(authorityOpened ? 'warn' : 'fail', authorityOpened ? 'opens' : 'did not open'),
          '.',
        ),
      ]),
    );
  }

  private ledgerCard(ledger: CostLedger): HTMLElement {
    const table = el('table');
    table.appendChild(el('caption', { text: 'Measured operations accumulated during this exact lifecycle run' }));
    table.appendChild(
      el('thead', {}, el('tr', {}, el('th', { text: 'Operation' }), el('th', { text: 'Actual count' }))),
    );
    const body = el('tbody');
    for (const [key, label] of LEDGER_LABELS) {
      body.appendChild(
        el(
          'tr',
          { attrs: { 'data-revocation-cost': key } },
          el('th', { attrs: { scope: 'row' }, text: label }),
          el('td', { class: 'num', text: String(ledger[key]) }),
        ),
      );
    }
    table.appendChild(body);
    const zeroPayloadWork = ledger.rewrapPayloadBytesWritten === 0;
    return outcomeBox(
      zeroPayloadWork ? 'pass' : 'fail',
      zeroPayloadWork ? 'Actual lifecycle cost ledger' : 'Unexpected payload rewrite cost',
      zeroPayloadWork ? 'REVOCATION_COSTS_MEASURED' : 'PAYLOAD_REWRITE_RECORDED',
      'These counters are incremented by completed model operations, including the authority escrow check above; they are not a hardcoded estimate.',
      {
        'data-revocation-case': 'cost-ledger',
        'data-payload-bytes-rewritten': String(ledger.rewrapPayloadBytesWritten),
      },
      scroller('Epoch lifecycle measured cost ledger', table),
    );
  }

  private scopeDisclosure(): HTMLDetailsElement {
    const block = disclosure(
      'What this epoch adaptation establishes—and what it does not',
      el(
        'ul',
        { class: 'honesty-list' },
        el(
          'li',
          {},
          'Future/current data: requiring ',
          el('code', { text: epochAttribute(2) }),
          ' and withholding Bob’s complete epoch-2 key keeps his old key out of an epoch-2 header.',
        ),
        el(
          'li',
          {},
          'History: a retained old key plus retained old header still opens. No cryptographic update erases plaintext, keys, DEKs, replicas, or snapshots already copied by a recipient.',
        ),
        el(
          'li',
          {},
          'Freshness: an authentic old header is detected only against separately trusted current state. If storage and its checkpoint roll back together, this local check cannot detect it.',
        ),
        el(
          'li',
          { attrs: { 'data-revocation-assumption': 'issuer-state' } },
          'Issuance assumption: a trusted application authenticates stable holder identifiers and authoritative business attributes, then integrity-protects monotonically advancing epoch, revocation and checkpoint state. This model implements no enrollment, alias prevention, key delivery, rollback-resistant issuer storage or multi-device state synchronization.',
        ),
        el(
          'li',
          { attrs: { 'data-revocation-nonclaim': 'public-update' } },
          'Update is owner-assisted and per selected record: the owner capability recovers the DEK. There is no public update token, server-only update, proxy-reencryption claim, or scalable bulk-revocation claim.',
        ),
        el(
          'li',
          { attrs: { 'data-revocation-nonclaim': 'construction' } },
          'This is not RW15, revocable ABE, revocable-storage ABE, or self-updatable encryption. It is an application-layer adaptation around single-authority FAME, HKDF-SHA-256, and AES-256-GCM.',
        ),
        el(
          'li',
          { attrs: { 'data-revocation-nonclaim': 'proof' } },
          'No proof combines FAME with this epoch gate, owner capsule, access wrapper, or trusted checkpoint. No production-hardening, deletion, side-channel, or availability claim is made.',
        ),
      ),
    );
    block.setAttribute('data-revocation-claim-scope', 'bounded-application-adaptation');
    return block;
  }

  private renderUnexpected(error: unknown): void {
    clear(this.resultHost);
    this.resultHost.appendChild(
      outcomeBox(
        'fail',
        'Epoch lesson error',
        'EPOCH_LESSON_ERROR',
        error instanceof Error ? error.message : 'An unexpected epoch-lifecycle error occurred.',
        { 'data-revocation-unexpected': 'true' },
      ),
    );
    this.busy = false;
    this.runButton.disabled = !this.initialized;
    this.element.removeAttribute('aria-busy');
  }
}

export function createEpochRevocationLesson(): EpochRevocationLesson {
  return new EpochRevocationLesson();
}
