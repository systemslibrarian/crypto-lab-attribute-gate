/**
 * Learner-facing FABESA CP-A2BE lesson.
 *
 * This panel is deliberately independent from the eight FAME exhibits. It
 * compares two equal-shape, equal-length hidden-value policies, then lets the
 * learner follow the bounded public-candidate search whose AES-GCM tag is the
 * only success oracle. The observer subtree never receives a hidden value or
 * plaintext node; the same-tab ground-truth disclosure sits outside it and is
 * explicitly labelled as a pedagogical role view, not an access boundary.
 */
import {
  G1_BYTES,
  G2_BYTES,
  GT_BYTES,
  g1ToHex,
  g2ToHex,
  gtToHex,
} from '../fame/bls';
import { secureRandom } from '../fame/rand';
import {
  FABESA_PAIRING_TERMS_PER_CANDIDATE,
  FABESA_PAPER,
  FabesaCiphertextError,
  MAX_RECONSTRUCTION_CANDIDATES,
  bytesToHex,
  enumerateReconstructionCandidates,
  keygen,
  openEnvelope,
  sealEnvelope,
  setup,
  type Authority,
  type FabesaEnvelope,
  type HiddenAttribute,
  type HiddenPolicy,
  type OpenEnvelopeResult,
  type PublicPolicy,
  type SecretKey,
} from '../fabesa';
import {
  append,
  button,
  clear,
  disclosure,
  el,
  liveRegion,
  scroller,
  section,
  select,
  statusChip,
  type Child,
} from './dom';

type WorldId = 'a' | 'b';
type KeyProfileId = 'alice' | 'wrong-values' | 'missing-names' | 'foreign-authority';
type ModificationId = 'intact' | 'flip-record' | 'malformed-envelope';

interface WorldDefinition {
  readonly label: string;
  readonly attributes: readonly [string, string, string];
  readonly record: string;
}

const WORLD: Record<WorldId, WorldDefinition> = {
  a: {
    label: 'World A',
    attributes: ['BLOCKED', 'CARD-017', 'RESEARCH'],
    record: 'CASE-004417 / Ward 3B / finding: CARDIAC / release: teaching-only',
  },
  b: {
    label: 'World B',
    attributes: ['PENDING', 'NEUR-204', 'CLINICAL'],
    record: 'CASE-009128 / Ward 7C / finding: SEIZURE / release: teaching-only',
  },
};

const PUBLIC_NAMES = ['Emergency', 'Department', 'Clearance'] as const;
const PUBLIC_STRUCTURE = 'Emergency OR (Department AND Clearance)';
const PUBLIC_MATRIX = 'M = [[1, 0], [1, 1], [0, -1]]';
const LESSON_CONTEXT = 'attribute-gate/fabesa-cp-a2be-lesson/v1';
const LESSON_RECORD_BYTES = new TextEncoder().encode(WORLD.a.record).length;

const PROFILE_LABELS: Record<KeyProfileId, string> = {
  alice: 'Alice: two public candidates; World A opens on the second',
  'wrong-values': 'All public names, but nonmatching hidden values',
  'missing-names': 'No public names from this policy',
  'foreign-authority': 'World A values, but a different authority',
};

function hiddenPolicy(world: WorldId): HiddenPolicy {
  const [emergency, department, clearance] = WORLD[world].attributes;
  return {
    rows: [
      { name: 'Emergency', value: emergency, vector: [1n, 0n] },
      { name: 'Department', value: department, vector: [1n, 1n] },
      { name: 'Clearance', value: clearance, vector: [0n, -1n] },
    ],
  };
}

function assertChallengeFixture(): void {
  const enc = new TextEncoder();
  if (WORLD.a.record === WORLD.b.record || enc.encode(WORLD.b.record).length !== LESSON_RECORD_BYTES) {
    throw new Error('FABESA_FIXTURE: challenge records must differ and have equal UTF-8 length');
  }
  WORLD.a.attributes.forEach((value, index) => {
    const other = WORLD.b.attributes[index];
    if (value === other || enc.encode(value).length !== enc.encode(other).length) {
      throw new Error(
        `FABESA_FIXTURE: hidden values at row ${index + 1} must differ and have equal UTF-8 length`,
      );
    }
  });
}

function profileAttributes(profile: Exclude<KeyProfileId, 'foreign-authority'>): readonly HiddenAttribute[] {
  switch (profile) {
    case 'alice':
      return [
        { name: 'Emergency', value: 'ENABLED' },
        { name: 'Department', value: 'CARD-017' },
        { name: 'Clearance', value: 'RESEARCH' },
      ];
    case 'wrong-values':
      return [
        { name: 'Emergency', value: 'DENIED!' },
        { name: 'Department', value: 'FIN-003X' },
        { name: 'Clearance', value: 'EXTERNAL' },
      ];
    case 'missing-names':
      return [
        { name: 'Region', value: 'WEST' },
        { name: 'Role', value: 'AUDITOR' },
      ];
  }
}

function cloneForModification(
  envelope: FabesaEnvelope,
  modification: ModificationId,
): FabesaEnvelope {
  const copy: FabesaEnvelope = {
    ...envelope,
    nonce: envelope.nonce.slice(),
    sealed: envelope.sealed.slice(),
  };
  if (modification === 'flip-record') {
    copy.sealed[0] ^= 1;
  } else if (modification === 'malformed-envelope') {
    return { ...copy, nonce: copy.nonce.slice(0, copy.nonce.length - 1) };
  }
  return copy;
}

function isExpectedFormatError(error: unknown): boolean {
  return (
    error instanceof FabesaCiphertextError ||
    (error instanceof Error && error.message.startsWith('FABESA_ENVELOPE:'))
  );
}

async function ciphertextFingerprint(envelope: FabesaEnvelope): Promise<string> {
  const material = [
    envelope.context,
    String(envelope.abe.policy.columns),
    ...envelope.abe.policy.rows.flatMap((row) => [
      String(row.index),
      row.name,
      ...row.vector.map(String),
    ]),
    ...envelope.abe.ct1.map(g1ToHex),
    g2ToHex(envelope.abe.ct2),
    g2ToHex(envelope.abe.ct3),
    g2ToHex(envelope.abe.ct4),
    gtToHex(envelope.abe.ct5),
    bytesToHex(envelope.nonce),
    bytesToHex(envelope.sealed),
  ].join('|');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return bytesToHex(new Uint8Array(digest));
}

function codeTag(code: string): HTMLElement {
  return el('span', { class: 'code-tag', text: code });
}

function outcomeBox(
  tone: 'pass' | 'fail' | 'warn' | 'neutral',
  headline: string,
  code: string,
  detail: string,
  ...children: Child[]
): HTMLElement {
  const outcome = tone === 'pass' ? 'opened' : tone === 'warn' ? 'blocked' : 'failed';
  const verdictClass = tone === 'pass' ? 'verdict-pass' : tone === 'warn' ? 'verdict-warn' : 'verdict-fail';
  return el(
    'div',
    {
      class: `verdict ${verdictClass}`,
      attrs: { 'data-outcome': outcome, 'data-code': code },
    },
    el('div', { class: 'verdict-head' }, statusChip(tone, headline), codeTag(code)),
    el('p', { class: 'verdict-detail', text: detail }),
    ...children,
  );
}

/**
 * A self-contained view object so App only has to append `element` and await
 * `initialize()`. Keeping its state separate prevents a FABESA reseal from
 * retiring or rewriting any FAME result.
 */
export class FabesaLesson {
  readonly element: HTMLElement;

  private authority: Authority | null = null;
  private foreignAuthority: Authority | null = null;
  private readonly keys = new Map<KeyProfileId, SecretKey>();
  private readonly envelopes = new Map<WorldId, FabesaEnvelope>();
  private readonly fingerprints = new Map<WorldId, string>();

  private selectedWorld: WorldId = 'a';
  private selectedProfile: KeyProfileId = 'alice';
  private selectedModification: ModificationId = 'intact';
  private initialized = false;
  private busy = false;
  private capKey: SecretKey | null = null;

  private readonly observerHost: HTMLElement;
  private readonly sealHost: HTMLElement;
  private readonly attemptHost: HTMLElement;
  private readonly capHost: HTMLElement;
  private readonly resealButton: HTMLButtonElement;
  private readonly openButton: HTMLButtonElement;
  private readonly capButton: HTMLButtonElement;

  constructor() {
    this.observerHost = el('div', {
      class: 'fabesa-observer',
      attrs: { 'data-host': 'fabesa-comparison', 'data-fabesa-role': 'observer' },
    });
    this.sealHost = liveRegion('FABESA sealing status');
    this.sealHost.setAttribute('data-host', 'fabesa-seal');
    this.attemptHost = liveRegion('FABESA candidate attempt result');
    this.attemptHost.setAttribute('data-host', 'fabesa-attempt');
    this.capHost = liveRegion('FABESA candidate-bound result');
    this.capHost.setAttribute('data-host', 'fabesa-cap');

    this.resealButton = button(
      'Reseal selected world',
      () => void this.resealSelected().catch((error: unknown) => this.renderUnexpected(error, this.sealHost)),
      'btn',
    );
    this.resealButton.id = 'fabesa-reseal';

    this.openButton = button(
      'Try bounded candidate opening',
      () => void this.tryOpen().catch((error: unknown) => this.renderUnexpected(error)),
      'btn btn-primary',
    );
    this.openButton.id = 'fabesa-open';

    this.capButton = button(
      'Run candidate-cap fixture',
      () => void this.runCandidateCap().catch((error: unknown) => this.renderUnexpected(error, this.capHost)),
      'btn',
    );
    this.capButton.id = 'fabesa-run-cap';

    const groundTruth = this.groundTruthDisclosure();
    groundTruth.id = 'fabesa-ground-truth';

    this.element = section(
      {
        id: 'fabesa',
        number: '09',
        title: 'Hide attribute values with bounded FABESA CP-A2BE',
        lede:
          'FAME hides the record but publishes its policy labels. This separate lesson runs FABESA so two different equal-length records expose the same attribute names, access structure, dimensions, and lengths while their attribute values differ. Open candidates one at a time and let AES-GCM tag acceptance—not an expected plaintext—recognize a hidden-value match.',
      },
      el(
        'div',
        { class: 'fabesa-controls stack-row' },
        select(
          'Ciphertext world',
          [
            { value: 'a', label: 'World A' },
            { value: 'b', label: 'World B' },
          ],
          (value) => this.chooseWorld(value),
          'fabesa-world',
          this.selectedWorld,
        ),
        this.resealButton,
      ),
      this.sealHost,
      this.observerHost,
      groundTruth,
      el('h3', { text: 'Try a key and follow each candidate' }),
      el(
        'p',
        { class: 'fabesa-explainer' },
        `Public names can identify a reconstruction without revealing whether its hidden values match. The opener therefore evaluates one candidate, derives a candidate key, and asks only whether the AES-GCM tag authenticates. A wrong candidate is rejected except with the tag's negligible forgery probability. Figure 5 contains ${FABESA_PAIRING_TERMS_PER_CANDIDATE} pairing terms per attempted candidate; the measured nonidentity pairing calls can be lower only in a degenerate identity case.`,
      ),
      el(
        'div',
        { class: 'fabesa-controls stack-row' },
        select(
          'Key profile',
          (Object.entries(PROFILE_LABELS) as [KeyProfileId, string][]).map(([value, label]) => ({
            value,
            label,
          })),
          (value) => this.chooseProfile(value),
          'fabesa-key-profile',
          this.selectedProfile,
        ),
        select(
          'Ciphertext condition',
          [
            { value: 'intact', label: 'Intact envelope' },
            { value: 'flip-record', label: 'Flip one sealed-record bit' },
            { value: 'malformed-envelope', label: 'Malformed: 11-byte nonce' },
          ],
          (value) => this.chooseModification(value),
          'fabesa-modification',
          this.selectedModification,
        ),
        this.openButton,
      ),
      this.attemptHost,
      el('h3', { text: 'Bound the public candidate search' }),
      el(
        'p',
        { class: 'fabesa-explainer' },
        `This profile permits at most ${MAX_RECONSTRUCTION_CANDIDATES} reconstruction candidates. The fixture uses ten matching public rows whose 2-of-10 matrix yields more candidates than that; it must refuse before any decryption pairing or tag trial.`,
      ),
      this.capButton,
      this.capHost,
      this.scopeBoundary(),
    );
    this.setControlsDisabled(true);
    this.element.setAttribute('aria-busy', 'true');
  }

  async initialize(): Promise<void> {
    if (this.initialized || this.busy) return;
    this.busy = true;
    clear(this.sealHost);
    this.sealHost.appendChild(statusChip('neutral', 'Preparing two fresh ciphertexts'));
    try {
      assertChallengeFixture();
      this.authority = setup(secureRandom);
      this.foreignAuthority = setup(secureRandom);
      this.keys.set(
        'alice',
        keygen(
          this.authority.pk,
          this.authority.msk,
          profileAttributes('alice'),
          secureRandom,
          'lesson-alice',
        ),
      );
      this.keys.set(
        'wrong-values',
        keygen(
          this.authority.pk,
          this.authority.msk,
          profileAttributes('wrong-values'),
          secureRandom,
          'lesson-wrong-values',
        ),
      );
      this.keys.set(
        'missing-names',
        keygen(
          this.authority.pk,
          this.authority.msk,
          profileAttributes('missing-names'),
          secureRandom,
          'lesson-missing-names',
        ),
      );
      this.keys.set(
        'foreign-authority',
        keygen(
          this.foreignAuthority.pk,
          this.foreignAuthority.msk,
          hiddenPolicy('a').rows,
          secureRandom,
          'lesson-foreign-authority',
        ),
      );

      // Keep setup/sealing sequential around the shared pairing instrument.
      await this.sealWorld('a');
      await this.sealWorld('b');
      this.initialized = true;
      this.renderObserver();
      clear(this.sealHost);
      this.sealHost.appendChild(
        outcomeBox(
          'pass',
          'Two fresh ciphertexts ready',
          'FABESA_SEALED',
          `World A and World B contain different ${LESSON_RECORD_BYTES}-byte records, the same public policy payload, and equal byte-length hidden values. Their randomized ciphertext fingerprints differ.`,
        ),
      );
      this.element.setAttribute('data-fabesa-ready', 'true');
    } catch (error) {
      this.renderUnexpected(error, this.sealHost);
      throw error;
    } finally {
      this.busy = false;
      this.element.removeAttribute('aria-busy');
      this.setControlsDisabled(!this.initialized);
    }
  }

  private async sealWorld(world: WorldId): Promise<void> {
    if (!this.authority) throw new Error('FABESA lesson authority is not initialized');
    const envelope = await sealEnvelope(
      this.authority.pk,
      hiddenPolicy(world),
      WORLD[world].record,
      secureRandom,
      LESSON_CONTEXT,
      `lesson-world-${world}`,
    );
    this.envelopes.set(world, envelope);
    this.fingerprints.set(world, await ciphertextFingerprint(envelope));
  }

  private async resealSelected(): Promise<void> {
    if (!this.initialized || this.busy) return;
    this.busy = true;
    this.setControlsDisabled(true);
    this.element.setAttribute('aria-busy', 'true');
    this.retireAttempt(`${WORLD[this.selectedWorld].label} was resealed`);
    clear(this.sealHost);
    this.sealHost.appendChild(statusChip('neutral', `Resealing ${WORLD[this.selectedWorld].label}`));
    try {
      await this.sealWorld(this.selectedWorld);
      this.renderObserver();
      clear(this.sealHost);
      this.sealHost.appendChild(
        outcomeBox(
          'pass',
          'Fresh ciphertext ready',
          'FABESA_SEALED',
          `${WORLD[this.selectedWorld].label} now has fresh ABE randomness, a fresh encapsulated secret, and a fresh AES-GCM nonce.`,
        ),
      );
    } finally {
      this.busy = false;
      this.element.removeAttribute('aria-busy');
      this.setControlsDisabled(false);
    }
  }

  private chooseWorld(value: string): void {
    if (value !== 'a' && value !== 'b') return;
    if (value === this.selectedWorld) return;
    this.selectedWorld = value;
    this.retireAttempt('the selected ciphertext world changed');
    this.renderObserver();
  }

  private chooseProfile(value: string): void {
    if (!(value in PROFILE_LABELS)) return;
    const next = value as KeyProfileId;
    if (next === this.selectedProfile) return;
    this.selectedProfile = next;
    this.retireAttempt('the key profile changed');
    this.renderObserver();
  }

  private chooseModification(value: string): void {
    if (value !== 'intact' && value !== 'flip-record' && value !== 'malformed-envelope') return;
    if (value === this.selectedModification) return;
    this.selectedModification = value;
    this.retireAttempt('the ciphertext condition changed');
  }

  private setControlsDisabled(disabled: boolean): void {
    this.resealButton.disabled = disabled;
    this.openButton.disabled = disabled;
    this.capButton.disabled = disabled;
    for (const control of this.element.querySelectorAll<HTMLSelectElement>('select')) {
      control.disabled = disabled;
    }
  }

  private renderObserver(): void {
    clear(this.observerHost);
    const selectedKey = this.keys.get(this.selectedProfile);
    const selectedEnvelope = this.envelopes.get(this.selectedWorld);
    let candidateText = 'not available while the lesson initializes';
    if (selectedKey && selectedEnvelope) {
      const enumeration = enumerateReconstructionCandidates(selectedEnvelope.abe.policy, selectedKey);
      candidateText = enumeration.ok
        ? `${enumeration.candidates.length} public-name reconstruction candidate${enumeration.candidates.length === 1 ? '' : 's'} for the selected key`
        : `candidate enumeration refused at its public bound (${enumeration.reason})`;
    }

    const comparison = el('div', { class: 'fabesa-comparison' });
    for (const world of ['a', 'b'] as const) {
      const envelope = this.envelopes.get(world);
      const fingerprint = this.fingerprints.get(world);
      comparison.appendChild(
        el(
          'article',
          {
            class: 'fabesa-world-card',
            attrs: {
              'data-fabesa-world': world,
              'data-selected': String(world === this.selectedWorld),
            },
          },
          el(
            'div',
            { class: 'fabesa-world-head' },
            el('h4', { text: WORLD[world].label }),
            world === this.selectedWorld ? statusChip('neutral', 'selected') : null,
          ),
          el('p', { class: 'fabesa-world-shape', text: PUBLIC_STRUCTURE }),
          el('p', {
            class: 'fabesa-world-meta',
            text: `${PUBLIC_NAMES.join(', ')} · 3 x 2 MSP · 3 G1 + 3 G2 + 1 GT`,
          }),
          el(
            'p',
            { class: 'fabesa-fingerprint' },
            el('span', { text: 'Ciphertext SHA-256 ' }),
            el('code', {
              text: fingerprint ? `${fingerprint.slice(0, 16)}…${fingerprint.slice(-12)}` : 'preparing…',
            }),
            envelope
              ? el('span', { text: ` · sealed record ${envelope.sealed.length} bytes` })
              : null,
          ),
        ),
      );
    }

    const leakage = el('table', { class: 'fabesa-leak-table' });
    leakage.appendChild(
      el('caption', {
        text: 'Exactly what the observer receives, and what this lesson keeps out of that view',
      }),
    );
    leakage.appendChild(
      el(
        'thead',
        {},
        el('tr', {}, el('th', { text: 'Field' }), el('th', { text: 'Visibility' }), el('th', { text: 'Observed value' })),
      ),
    );
    const body = el('tbody');
    const publicRows: readonly [string, string, string][] = [
      ['names', 'Attribute names', PUBLIC_NAMES.join(', ')],
      ['structure', 'Boolean structure', PUBLIC_STRUCTURE],
      ['msp', 'Monotone span program', PUBLIC_MATRIX],
      ['dimensions', 'Matrix dimensions', '3 rows x 2 columns'],
      [
        'element-counts',
        'Public ABE group elements',
        `Full ct1[1..3], ct2, ct3, ct4, and ct5 encodings are public: 3 G1 (${3 * G1_BYTES} B) + 3 G2 (${3 * G2_BYTES} B) + 1 GT (${GT_BYTES} B) = ${3 * G1_BYTES + 3 * G2_BYTES + GT_BYTES} B. The cards abbreviate them with one digest.`,
      ],
      [
        'public-key',
        'Public authority key',
        `Full g3, B1, B2, and EAlpha encodings are public: 1 G1 + 2 G2 + 1 GT = ${G1_BYTES + 2 * G2_BYTES + GT_BYTES} B. The fixed BLS12-381 parameters and versioned H/DST definition are public too.`,
      ],
      [
        'context-aad',
        'Public context and AAD',
        `Context "${LESSON_CONTEXT}"; the authenticated data also carries the complete public policy payload`,
      ],
      [
        'nonce',
        'Public AES-GCM nonce',
        selectedEnvelope
          ? `${selectedEnvelope.nonce.length} bytes: ${bytesToHex(selectedEnvelope.nonce)}`
          : 'preparing…',
      ],
      [
        'record-length',
        'Public ciphertext/tag length',
        selectedEnvelope
          ? `All ${selectedEnvelope.sealed.length} bytes are public, including the 16-byte GCM tag; the cards display only the length`
          : 'preparing…',
      ],
      [
        'key-names',
        'Selected key names',
        selectedKey ? selectedKey.names.join(', ') : 'preparing…',
      ],
      ['candidate-count', 'Public candidate count', candidateText],
    ];
    for (const [leak, label, value] of publicRows) {
      body.appendChild(
        el(
          'tr',
          { attrs: { 'data-fabesa-leak': leak, 'data-visibility': 'public' } },
          el('th', { attrs: { scope: 'row' }, text: label }),
          el('td', {}, statusChip('neutral', 'public')),
          el('td', { text: value }),
        ),
      );
    }
    for (const [leak, label] of [
      ['values', 'Attribute values'],
      ['plaintext', 'Record plaintext'],
    ] as const) {
      body.appendChild(
        el(
          'tr',
          {
            class: 'fabesa-hidden-row',
            attrs: { 'data-fabesa-leak': leak, 'data-visibility': 'hidden' },
          },
          el('th', { attrs: { scope: 'row' }, text: label }),
          el('td', {}, statusChip('neutral', 'withheld')),
          el('td', { text: 'not present in this observer view' }),
        ),
      );
    }
    leakage.appendChild(body);

    append(this.observerHost, [
      el('h3', { text: 'Public observer comparison' }),
      el(
        'p',
        { class: 'fabesa-explainer' },
        'The fingerprints differ, as expected for separately randomized encryptions of different hidden inputs. That difference does not identify which values were used: both cards expose the same public shape and size profile.',
      ),
      comparison,
      scroller('FABESA public leakage table', leakage),
    ]);
  }

  private groundTruthDisclosure(): HTMLDetailsElement {
    const table = el('table', { class: 'fabesa-ground-table' });
    table.appendChild(
      el('caption', {
        text: 'Encryptor-only lesson fixture: different values with equal UTF-8 byte lengths',
      }),
    );
    table.appendChild(
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { text: 'Public name' }),
          el('th', { text: 'World A hidden value' }),
          el('th', { text: 'World B hidden value' }),
          el('th', { class: 'num', text: 'Bytes each' }),
        ),
      ),
    );
    const body = el('tbody');
    PUBLIC_NAMES.forEach((name, index) => {
      const a = WORLD.a.attributes[index];
      const b = WORLD.b.attributes[index];
      body.appendChild(
        el(
          'tr',
          {},
          el('th', { attrs: { scope: 'row' }, text: name }),
          el('td', {}, el('code', { text: a })),
          el('td', {}, el('code', { text: b })),
          el('td', { class: 'num', text: String(new TextEncoder().encode(a).length) }),
        ),
      );
    });
    table.appendChild(body);

    return disclosure(
      'Encryptor-only ground truth: inspect the hidden values and equal-length condition',
      el(
        'p',
        {},
        'This disclosure is outside the observer subtree, but it is not a security boundary. All roles run in one browser tab so a learner can audit the fixture.',
      ),
      scroller('FABESA hidden-value ground-truth table', table),
      el(
        'p',
        {},
        el('strong', { text: 'World A record: ' }),
        el('code', { text: WORLD.a.record, attrs: { 'data-fabesa-record-world': 'a' } }),
      ),
      el(
        'p',
        {},
        el('strong', { text: 'World B record: ' }),
        el('code', { text: WORLD.b.record, attrs: { 'data-fabesa-record-world': 'b' } }),
      ),
      el(
        'p',
        {},
        'The records are different but each is ',
        el('strong', { text: `${LESSON_RECORD_BYTES} UTF-8 bytes` }),
        '. Equal challenge-message length is preserved as well as equal policy-value lengths.',
      ),
    );
  }

  private async tryOpen(): Promise<void> {
    if (!this.initialized || this.busy) return;
    const envelope = this.envelopes.get(this.selectedWorld);
    const key = this.keys.get(this.selectedProfile);
    if (!envelope || !key) return;

    this.busy = true;
    this.setControlsDisabled(true);
    clear(this.attemptHost);
    this.attemptHost.appendChild(statusChip('neutral', 'Evaluating public candidates'));
    try {
      const candidateEnvelope = cloneForModification(envelope, this.selectedModification);
      let result: OpenEnvelopeResult;
      try {
        result = await openEnvelope(candidateEnvelope, key);
      } catch (error) {
        if (!isExpectedFormatError(error)) {
          this.renderUnexpected(error, this.attemptHost, true);
          return;
        }
        clear(this.attemptHost);
        this.attemptHost.appendChild(
          outcomeBox(
            'fail',
            'Malformed envelope rejected',
            'MALFORMED_FABESA_CIPHERTEXT',
            error instanceof Error
              ? `Parsing/validation stopped before a candidate result: ${error.message}`
              : 'Parsing/validation stopped before a candidate result.',
            this.pairingFact(0, 0),
          ),
        );
        return;
      }
      this.renderOpenResult(candidateEnvelope, result);
    } finally {
      this.busy = false;
      this.setControlsDisabled(false);
    }
  }

  private renderOpenResult(envelope: FabesaEnvelope, result: OpenEnvelopeResult): void {
    clear(this.attemptHost);
    const ledger = this.attemptLedger(envelope, result);
    if (result.ok) {
      this.attemptHost.appendChild(
        outcomeBox(
          'pass',
          'Candidate tag accepted',
          'FABESA_OPENED',
          `Candidate ${result.attempts.length} derived the key under which the AES-GCM tag verified. This recognizes a candidate; it does not authenticate who created the envelope. The opener was not given an expected plaintext or target group element.`,
          ledger,
          this.pairingFact(result.pairings, result.attempts.length),
          el('pre', {
            class: 'fabesa-plaintext',
            text: result.plaintext,
            attrs: {
              'data-fabesa-plaintext': 'revealed',
              role: 'group',
              'aria-label': 'FABESA revealed plaintext',
              tabindex: '0',
            },
          }),
        ),
      );
      return;
    }

    if (result.reason === 'NO_PUBLIC_RECONSTRUCTION') {
      this.attemptHost.appendChild(
        outcomeBox(
          'warn',
          'Public names cannot satisfy the policy',
          'PUBLIC_NAMES_UNSATISFIED',
          'No public-name reconstruction exists, so the opener stopped before any pairing or AEAD trial. This structural fact is intentionally public.',
          ledger,
          this.pairingFact(0, 0),
        ),
      );
      return;
    }

    if (result.reason === 'NO_CANDIDATE_OPENED') {
      this.attemptHost.appendChild(
        outcomeBox(
          'fail',
          'No candidate tag accepted',
          'NO_CANDIDATE_AUTHENTICATED',
          'The same failure covers nonmatching hidden values, a modified sealed record, and components issued by another authority. The tag oracle does not identify which cause occurred.',
          ledger,
          this.pairingFact(result.pairings, result.attempts.length),
        ),
      );
      return;
    }

    this.attemptHost.appendChild(
      outcomeBox(
        'warn',
        'Candidate bound stopped the opening',
        'CANDIDATE_LIMIT_EXCEEDED',
        `The bounded enumerator refused with ${result.reason}; it did not continue speculatively.`,
        ledger,
        this.pairingFact(result.pairings, result.attempts.length),
      ),
    );
  }

  private attemptLedger(envelope: FabesaEnvelope, result: OpenEnvelopeResult): HTMLElement {
    if (result.attempts.length === 0) {
      return el('p', {
        class: 'fabesa-no-attempts',
        text: 'Candidate ledger: no cryptographic candidate was attempted.',
      });
    }
    const table = el('table', { class: 'fabesa-attempts' });
    table.appendChild(
      el('caption', {
        text: 'Sequential public reconstruction candidates and the authenticated-tag oracle',
      }),
    );
    table.appendChild(
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { class: 'num', text: 'Candidate' }),
          el('th', { text: 'Public rows used' }),
          el('th', { class: 'num', text: 'Figure 5 terms' }),
          el('th', { class: 'num', text: 'Executed pairings' }),
          el('th', { text: 'AES-GCM tag' }),
        ),
      ),
    );
    const body = el('tbody');
    result.attempts.forEach((attempt, index) => {
      const names = attempt.candidate.terms.map(
        (term) => envelope.abe.policy.rows[term.rowIndex - 1]?.name ?? `row ${term.rowIndex}`,
      );
      body.appendChild(
        el(
          'tr',
          {
            attrs: {
              'data-candidate': String(index + 1),
              'data-pairings': String(attempt.pairings),
              'data-pairing-terms': String(FABESA_PAIRING_TERMS_PER_CANDIDATE),
              'data-aead': attempt.tagAccepted ? 'accepted' : 'rejected',
            },
          },
          el('td', { class: 'num', text: String(index + 1) }),
          el('td', { text: names.join(' + ') }),
          el('td', { class: 'num', text: String(FABESA_PAIRING_TERMS_PER_CANDIDATE) }),
          el('td', { class: 'num', text: String(attempt.pairings) }),
          el('td', {}, statusChip(attempt.tagAccepted ? 'pass' : 'fail', attempt.tagAccepted ? 'accepted' : 'rejected')),
        ),
      );
    });
    table.appendChild(body);
    return scroller('FABESA candidate-attempt ledger', table);
  }

  private pairingFact(pairings: number, attempts: number): HTMLElement {
    const nominalTerms = attempts * FABESA_PAIRING_TERMS_PER_CANDIDATE;
    return el(
      'p',
      { class: 'fabesa-pairing-total' },
      el('strong', { text: 'Pairing accounting: ' }),
      el('span', {
        text: `${nominalTerms} Figure 5 terms across ${attempts} attempted candidate${attempts === 1 ? '' : 's'}; ${pairings} nonidentity pairing calls executed`,
        attrs: {
          'data-total-pairing-terms': String(nominalTerms),
          'data-total-pairings': String(pairings),
        },
      }),
    );
  }

  private async runCandidateCap(): Promise<void> {
    if (!this.initialized || this.busy || !this.authority) return;
    this.busy = true;
    this.setControlsDisabled(true);
    clear(this.capHost);
    this.capHost.appendChild(statusChip('neutral', 'Enumerating bounded public candidates'));
    try {
      const attributes = Array.from({ length: 10 }, (_, index) => ({
        name: `Choice-${String(index + 1).padStart(2, '0')}`,
        value: `VALUE-${String(index + 1).padStart(2, '0')}`,
      }));
      this.capKey ??= keygen(
        this.authority.pk,
        this.authority.msk,
        attributes,
        secureRandom,
        'lesson-cap-fixture',
      );
      const policy: PublicPolicy = {
        columns: 2,
        rows: attributes.map((attribute, index) => ({
          index: index + 1,
          name: attribute.name,
          vector: [1n, BigInt(index + 1)],
        })),
      };
      const result = enumerateReconstructionCandidates(policy, this.capKey);
      clear(this.capHost);
      if (!result.ok && result.reason === 'CANDIDATE_BOUND_EXCEEDED') {
        this.capHost.appendChild(
          outcomeBox(
            'warn',
            'Candidate cap enforced before decryption',
            'CANDIDATE_LIMIT_EXCEEDED',
            `Every pair of the ten distinct public rows reconstructs the target. Candidate 33 exceeded the configured maximum of ${result.limit}, so enumeration stopped after examining ${result.subsetsExamined} subsets.`,
            el(
              'ul',
              { class: 'fabesa-limit-facts' },
              el('li', { text: `${result.matchedRows.length} matched public rows; 45 possible pairs.` }),
              el('li', { text: `${result.limit} candidates retained; the next candidate caused refusal.` }),
              el('li', {}, 'Cryptographic candidate attempts: ', el('strong', { text: '0' })),
              el(
                'li',
                {},
                'Pairings and AEAD trials: ',
                el('strong', {
                  text: '0',
                  attrs: { 'data-total-pairings': '0', 'data-total-pairing-terms': '0' },
                }),
              ),
            ),
          ),
        );
      } else {
        this.capHost.appendChild(
          outcomeBox(
            'fail',
            'Candidate-cap fixture did not refuse',
            'FABESA_FIXTURE_ERROR',
            'The teaching fixture failed its own assertion; do not infer a bound from this run.',
          ),
        );
      }
    } finally {
      this.busy = false;
      this.setControlsDisabled(false);
    }
  }

  private retireAttempt(reason: string): void {
    if (this.attemptHost.childElementCount === 0) return;
    clear(this.attemptHost);
    this.attemptHost.appendChild(
      el(
        'div',
        { class: 'verdict verdict-warn', attrs: { 'data-retired': 'true' } },
        el('div', { class: 'verdict-head' }, statusChip('warn', 'Result retired')),
        el('p', { class: 'verdict-detail', text: `Retired because ${reason}. Run the opening again.` }),
      ),
    );
  }

  private scopeBoundary(): HTMLElement {
    return el(
      'div',
      { class: 'fabesa-scope' },
      el('h3', { text: 'The theorem and this browser adaptation are different claims' }),
      el(
        'div',
        { class: 'fabesa-scope-grid' },
        el(
          'article',
          { class: 'fabesa-scope-card', attrs: { 'data-scope': 'theorem' } },
          el('h4', { text: 'Paper theorem' }),
          el(
            'p',
            {},
            el(
              'a',
              {
                text: 'FABESA, Theorem 4 (ePrint 2024/986)',
                attrs: { href: FABESA_PAPER, target: '_blank', rel: 'noreferrer' },
              },
            ),
            ' proves adaptive anonymity for the paper construction in the random-oracle model under the DLIN assumption, using the paper\'s asymmetric Type-III formulation in both G1 and G2. The two challenge policies must have an identical public payload—the same matrix, row-to-name map, names, and exposed sizes—challenge messages must be equal-size, and every queried key must satisfy neither challenge policy.',
          ),
          el(
            'p',
            {},
            'The operational Alice and foreign-authority exercises above are not an anonymity-game transcript. They exist to expose decryption behavior, including profiles that would be inadmissible as theorem-game key queries.',
          ),
        ),
        el(
          'article',
          { class: 'fabesa-scope-card', attrs: { 'data-scope': 'lab' } },
          el('h4', { text: 'Bounded hybrid lesson' }),
          el(
            'p',
            {},
            'The lab transcribes the CP-A2BE equations over BLS12-381, then adds canonical encodings, a finite public-candidate search, HKDF-SHA-256, and AES-256-GCM so a tag can authenticate a candidate-derived key. That KEM/DEM composition is a teaching adaptation; this page does not transfer Theorem 4 to it.',
          ),
          el(
            'p',
            {},
            `Among policy fields, only attribute values are hidden; the record plaintext is encrypted too. Names, structure, dimensions, element and record lengths, key attribute names, candidate counts, and success/failure outcomes remain visible. Search stops at ${MAX_RECONSTRUCTION_CANDIDATES} candidates. The code is neither production-hardened nor claimed constant-time.`,
          ),
          el(
            'p',
            {},
            'AES-GCM is only a candidate-recognition and integrity oracle under the candidate-derived key. It does not establish sender or ciphertext provenance, and this public-encryption hybrid has no CCA-security claim: anyone with the public key can form a new valid envelope.',
          ),
          el(
            'p',
            {},
            'Observer, encryptor, and key-holder views share this tab. Their separation teaches the information boundary; it does not provide process isolation.',
          ),
        ),
      ),
    );
  }

  private renderUnexpected(
    error: unknown,
    host = this.attemptHost,
    openingAborted = false,
  ): void {
    clear(host);
    host.appendChild(
      outcomeBox(
        'fail',
        'Lesson error',
        'FABESA_LESSON_ERROR',
        error instanceof Error ? error.message : 'An unexpected lesson error occurred.',
        !openingAborted
          ? null
          : el(
              'p',
              { class: 'fabesa-pairing-total' },
              el('strong', { text: 'Pairing accounting: ' }),
              el('span', { text: 'not claimed because the operation aborted unexpectedly' }),
            ),
      ),
    );
  }
}

export function createFabesaLesson(): FabesaLesson {
  return new FabesaLesson();
}
