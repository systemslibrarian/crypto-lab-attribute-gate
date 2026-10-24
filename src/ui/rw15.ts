/**
 * Learner-facing RW15 decentralized multi-authority CP-ABE lesson.
 *
 * This exhibit is deliberately separate from the FAME and FABESA lessons. It
 * executes the RW15 equations for independently issued, authority-qualified
 * attributes and makes the deployment assumptions that the equations do not
 * provide visible beside the results.
 */
import {
  g1ToHex,
  g2ToHex,
  gtEquals,
  gtToHex,
  type GTElement,
} from '../fame/bls';
import { secureRandom } from '../fame/rand';
import {
  compileRwPolicy,
  formatRwPolicy,
  reconstructRw,
  rwAnd,
  rwAttr,
  rwAuthoritySetup,
  rwDecrypt,
  rwEncrypt,
  rwKeygen,
  rwOpenRecord,
  rwOr,
  rwRandomGT,
  rwRawDecrypt,
  rwSealRecord,
  type RwAttributeKey,
  type RwAuthority,
  type RwCiphertext,
  type RwLsss,
  type RwSealedRecord,
} from '../rw15';
import {
  button,
  clear,
  disclosure,
  el,
  formula,
  liveRegion,
  scroller,
  section,
  shortHex,
  statusChip,
  type Child,
} from './dom';

const HOSPITAL = 'Hospital';
const BOARD = 'Board';
const DOCTOR = `Doctor@${HOSPITAL}`;
const CARDIOLOGY = `Cardiology@${BOARD}`;

const ALICE_GID = 'gid:alice';
const BOB_GID = 'gid:bob';
const EVE_GID = 'gid:eve';
const MALLORY_GID = 'gid:mallory';

const CROSS_RECORD = 'CASE-0317: independently authorized cardiology record';
const HOSPITAL_RECORD = 'CASE-0317: hospital-only routing note';
const PAPER_URL = 'https://doi.org/10.1007/978-3-662-47854-7_19';
const IMPLEMENTATION_URL = 'https://jhuisi.github.io/charm/_modules/abenc_maabe_rw15.html';

interface RwFixture {
  readonly lsss: RwLsss;
  readonly shared: GTElement;
  readonly ciphertext: RwCiphertext;
  readonly sealed: RwSealedRecord;
  readonly fingerprint: string;
}

interface LessonKeys {
  readonly aliceDoctor: RwAttributeKey;
  readonly aliceCardiology: RwAttributeKey;
  readonly bobDoctor: RwAttributeKey;
  readonly eveCardiology: RwAttributeKey;
}

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

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return hex(new Uint8Array(digest));
}

async function authorityFingerprint(authority: RwAuthority): Promise<string> {
  return sha256(
    `RW15-authority-public-key-v1|${gtToHex(authority.pk.egga)}|${g1ToHex(authority.pk.gy)}`,
  );
}

async function keyFingerprint(key: RwAttributeKey): Promise<string> {
  return sha256(
    `${key.gid}|${key.attribute}|${key.authority}|${g2ToHex(key.K)}|${g1ToHex(key.KPrime)}`,
  );
}

async function ciphertextFingerprint(ciphertext: RwCiphertext): Promise<string> {
  return sha256(
    [
      formatRwPolicy(ciphertext.lsss.policy),
      gtToHex(ciphertext.C0),
      ...ciphertext.rows.flatMap((row) => [
        String(row.rowIndex),
        row.attribute,
        gtToHex(row.C1),
        g1ToHex(row.C2),
        g1ToHex(row.C3),
        g2ToHex(row.C4),
      ]),
    ].join('|'),
  );
}

function gtFingerprint(label: string, value: GTElement): HTMLElement {
  return el(
    'span',
    {},
    `${label} `,
    el('code', { text: shortHex(gtToHex(value), 16, 12) }),
  );
}

function pairingFact(rows: number, actual: number): Child {
  return el(
    'span',
    {},
    `${rows} selected row${rows === 1 ? '' : 's'} × 3 pairing terms; `,
    el('strong', { text: `${actual} actual non-identity pairing call${actual === 1 ? '' : 's'}` }),
    '.',
  );
}

function makeCrossPolicy(): RwLsss {
  return compileRwPolicy(
    rwAnd(
      [
        rwAttr(DOCTOR, 'rw-doctor-cross'),
        rwAttr(CARDIOLOGY, 'rw-cardiology-cross'),
      ],
      'rw-two-authority-and',
    ),
  );
}

function makeHospitalPolicy(): RwLsss {
  return compileRwPolicy(rwAttr(DOCTOR, 'rw-doctor-only'));
}

function repeatedAttributeFixture(): {
  readonly lsss: RwLsss;
  readonly usedRows: readonly number[];
  readonly satisfied: boolean;
} {
  const lsss = compileRwPolicy(
    rwAnd(
      [
        rwOr(
          [
            rwAttr('STUDENT@UT', 'rw-student-first'),
            rwAttr('PROFESSOR@OU', 'rw-professor'),
          ],
          'rw-repeat-left',
        ),
        rwOr(
          [
            rwAttr('STUDENT@UT', 'rw-student-second'),
            rwAttr('MASTERS@OU', 'rw-masters'),
          ],
          'rw-repeat-right',
        ),
      ],
      'rw-repeat-and',
    ),
  );
  const reconstruction = reconstructRw(lsss, new Set(['STUDENT@UT']));
  return {
    lsss,
    usedRows: reconstruction.usedRows,
    satisfied: reconstruction.satisfied,
  };
}

/** A self-contained view; App appends `element` and awaits `initialize()`. */
export class Rw15Lesson {
  readonly element: HTMLElement;

  private hospital: RwAuthority | null = null;
  private board: RwAuthority | null = null;
  private keys: LessonKeys | null = null;
  private crossFixture: RwFixture | null = null;
  private hospitalFixture: RwFixture | null = null;
  private initialized = false;
  private busy = false;

  private readonly setupHost: HTMLElement;
  private readonly sameGidHost: HTMLElement;
  private readonly crossGidHost: HTMLElement;
  private readonly compromiseHost: HTMLElement;
  private readonly sameGidButton: HTMLButtonElement;
  private readonly crossGidButton: HTMLButtonElement;
  private readonly compromiseButton: HTMLButtonElement;

  constructor() {
    this.setupHost = liveRegion('RW15 authority and key setup status');
    this.setupHost.setAttribute('data-host', 'rw15-setup');

    this.sameGidHost = liveRegion('RW15 same-GID decryption result');
    this.sameGidHost.setAttribute('data-host', 'rw15-same-gid');
    this.crossGidHost = liveRegion('RW15 cross-GID raw combination result');
    this.crossGidHost.setAttribute('data-host', 'rw15-cross-gid');
    this.compromiseHost = liveRegion('RW15 compromised-authority result');
    this.compromiseHost.setAttribute('data-host', 'rw15-compromise');

    this.sameGidButton = button(
      'Combine Alice’s two authority keys',
      () => void this.runSameGid().catch((error: unknown) => this.renderUnexpected(error, this.sameGidHost)),
      'btn btn-primary',
    );
    this.sameGidButton.id = 'rw15-run-same-gid';
    this.sameGidButton.setAttribute('data-rw15-action', 'same-gid');

    this.crossGidButton = button(
      'Pool Bob and Eve’s raw row terms',
      () => void this.runCrossGid().catch((error: unknown) => this.renderUnexpected(error, this.crossGidHost)),
    );
    this.crossGidButton.id = 'rw15-run-cross-gid';
    this.crossGidButton.setAttribute('data-rw15-action', 'cross-gid');

    this.compromiseButton = button(
      'Compromise Hospital and mint a key',
      () => void this.runCompromise().catch((error: unknown) => this.renderUnexpected(error, this.compromiseHost)),
    );
    this.compromiseButton.id = 'rw15-run-compromise';
    this.compromiseButton.setAttribute('data-rw15-action', 'compromise');

    this.element = section(
      {
        id: 'rw15',
        number: '10',
        title: 'Combine independent issuers with RW15',
        lede:
          'Hospital and Board run independent authority setups, then issue authority-qualified components bound to one byte-exact global identifier. Execute the successful same-GID path, bypass the normal interface to try the strongest raw cross-user pool, and see exactly what one compromised issuer can and cannot mint.',
      },
      el('h3', { text: 'Independent authority setup' }),
      el(
        'p',
        {},
        'The labels are namespace-qualified: ',
        el('code', { text: DOCTOR }),
        ' and ',
        el('code', { text: CARDIOLOGY }),
        '. Matching text from a different authority is a different cryptographic attribute.',
      ),
      this.setupHost,
      el('h3', { text: '1. Same canonical GID across both authorities' }),
      el(
        'p',
        {},
        'Hospital and Board each issue to the exact canonical identifier ',
        el('code', { text: ALICE_GID, attrs: { 'data-rw15-gid': 'alice' } }),
        '. The two-row ',
        el('code', { text: `${DOCTOR} AND ${CARDIOLOGY}` }),
        ' policy should reconstruct one shared target-group element and authenticate the sealed record.',
      ),
      this.sameGidButton,
      this.sameGidHost,
      el('h3', { text: '2. Raw cross-GID pool' }),
      el(
        'p',
        {},
        'Bob holds ',
        el('code', { text: DOCTOR }),
        ' for ',
        el('code', { text: BOB_GID, attrs: { 'data-rw15-gid': 'bob' } }),
        '; Eve holds ',
        el('code', { text: CARDIOLOGY }),
        ' for ',
        el('code', { text: EVE_GID, attrs: { 'data-rw15-gid': 'eve' } }),
        '. The raw combiner deliberately uses each owner’s own H(GID), so no metadata guard gets credit for the failure.',
      ),
      this.crossGidButton,
      this.crossGidHost,
      el('h3', { text: '3. Compromise one issuer' }),
      el(
        'p',
        {},
        'Treat Hospital’s master secret as stolen and mint ',
        el('code', { text: DOCTOR }),
        ' for ',
        el('code', { text: MALLORY_GID, attrs: { 'data-rw15-gid': 'mallory' } }),
        '. That must break a Hospital-only policy, but it cannot create Board’s independently controlled component for the two-authority policy.',
      ),
      this.compromiseButton,
      this.compromiseHost,
      this.repeatedAttributeDisclosure(),
      this.constructionDisclosure(),
    );

    this.setControlsDisabled(true);
    this.element.setAttribute('aria-busy', 'true');
  }

  async initialize(): Promise<void> {
    if (this.initialized || this.busy) return;
    this.busy = true;
    clear(this.setupHost);
    this.setupHost.appendChild(statusChip('neutral', 'Generating two independent authorities'));
    try {
      const hospital = rwAuthoritySetup(HOSPITAL, secureRandom, 'lesson-hospital');
      const board = rwAuthoritySetup(BOARD, secureRandom, 'lesson-board');
      const aliceDoctor = rwKeygen(hospital.sk, ALICE_GID, DOCTOR, secureRandom, 'alice-doctor').key;
      const aliceCardiology = rwKeygen(
        board.sk,
        ALICE_GID,
        CARDIOLOGY,
        secureRandom,
        'alice-cardiology',
      ).key;
      const bobDoctor = rwKeygen(hospital.sk, BOB_GID, DOCTOR, secureRandom, 'bob-doctor').key;
      const eveCardiology = rwKeygen(
        board.sk,
        EVE_GID,
        CARDIOLOGY,
        secureRandom,
        'eve-cardiology',
      ).key;

      const publicKeys = new Map([
        [hospital.pk.id, hospital.pk],
        [board.pk.id, board.pk],
      ]);
      const crossFixture = await this.sealFixture(
        publicKeys,
        makeCrossPolicy(),
        CROSS_RECORD,
        'two-authority-record',
      );
      const hospitalFixture = await this.sealFixture(
        publicKeys,
        makeHospitalPolicy(),
        HOSPITAL_RECORD,
        'hospital-only-record',
      );

      this.hospital = hospital;
      this.board = board;
      this.keys = { aliceDoctor, aliceCardiology, bobDoctor, eveCardiology };
      this.crossFixture = crossFixture;
      this.hospitalFixture = hospitalFixture;
      this.initialized = true;
      await this.renderSetup();
      this.element.setAttribute('data-rw15-ready', 'true');
    } catch (error) {
      this.renderUnexpected(error, this.setupHost);
      throw error;
    } finally {
      this.busy = false;
      this.element.removeAttribute('aria-busy');
      this.setControlsDisabled(!this.initialized);
    }
  }

  private async sealFixture(
    publicKeys: ReadonlyMap<string, RwAuthority['pk']>,
    lsss: RwLsss,
    plaintext: string,
    label: string,
  ): Promise<RwFixture> {
    const shared = rwRandomGT(secureRandom, label).element;
    const ciphertext = rwEncrypt(publicKeys, lsss, shared, secureRandom, label).ciphertext;
    const aad = `RW15-v1|${formatRwPolicy(lsss.policy)}|${[...publicKeys.keys()].sort().join(',')}`;
    const sealed = await rwSealRecord(shared, plaintext, aad, secureRandom, label);
    return {
      lsss,
      shared,
      ciphertext,
      sealed,
      fingerprint: await ciphertextFingerprint(ciphertext),
    };
  }

  private async renderSetup(): Promise<void> {
    if (!this.hospital || !this.board || !this.keys || !this.crossFixture) return;
    const [hospitalFp, boardFp, aliceDoctorFp, aliceCardiologyFp] = await Promise.all([
      authorityFingerprint(this.hospital),
      authorityFingerprint(this.board),
      keyFingerprint(this.keys.aliceDoctor),
      keyFingerprint(this.keys.aliceCardiology),
    ]);
    clear(this.setupHost);
    this.setupHost.appendChild(
      outcomeBox(
        'pass',
        'Independent public keys and GID-bound components ready',
        'RW15_READY',
        'The fingerprints below are computed from the actual in-browser public keys and issued components; no authority shares a master secret with the other.',
        { 'data-rw15-authorities': '2' },
        el(
          'div',
          { class: 'grid-2' },
          this.authorityCard(HOSPITAL, DOCTOR, hospitalFp),
          this.authorityCard(BOARD, CARDIOLOGY, boardFp),
        ),
        facts([
          el(
            'span',
            {},
            'Alice exact GID ',
            el('code', { text: ALICE_GID }),
            '; Hospital component SHA-256 ',
            el('code', { text: shortHex(aliceDoctorFp, 16, 12) }),
            '; Board component SHA-256 ',
            el('code', { text: shortHex(aliceCardiologyFp, 16, 12) }),
            '.',
          ),
          el(
            'span',
            {},
            'Two-authority ciphertext SHA-256 ',
            el('code', { text: shortHex(this.crossFixture.fingerprint, 16, 12) }),
            '.',
          ),
        ]),
      ),
    );
  }

  private authorityCard(authority: string, attribute: string, fingerprint: string): HTMLElement {
    return el(
      'article',
      {
        class: 'verdict',
        attrs: { 'data-rw15-authority': authority },
      },
      el('h4', { text: `${authority} authority` }),
      el('p', {}, el('strong', { text: 'Controlled label: ' }), el('code', { text: attribute })),
      el(
        'p',
        { class: 'verdict-plain' },
        'Public-key SHA-256 ',
        el('code', { text: shortHex(fingerprint, 16, 12) }),
      ),
    );
  }

  private async runSameGid(): Promise<void> {
    if (!this.initialized || this.busy || !this.keys || !this.crossFixture) return;
    this.beginAction(this.sameGidHost, 'Combining Alice’s independently issued components');
    try {
      const result = rwDecrypt(
        this.crossFixture.ciphertext,
        ALICE_GID,
        [this.keys.aliceDoctor, this.keys.aliceCardiology],
      );
      if (!result.ok) {
        clear(this.sameGidHost);
        this.sameGidHost.appendChild(
          outcomeBox(
            'fail',
            'Same-GID policy was not satisfied',
            result.code,
            'The live cryptographic result did not meet the expected two-row policy.',
            {
              'data-rw15-case': 'same-gid',
              'data-policy-satisfied': 'false',
              'data-aead-accepted': 'false',
              'data-recovered-matches': 'false',
            },
          ),
        );
        return;
      }
      const matches = gtEquals(result.recovered, this.crossFixture.shared);
      const opened = await rwOpenRecord(result.recovered, this.crossFixture.sealed);
      const passed = matches && opened.ok;
      clear(this.sameGidHost);
      this.sameGidHost.appendChild(
        outcomeBox(
          passed ? 'pass' : 'fail',
          passed ? 'Same GID opened the two-authority record' : 'Same-GID recovery failed',
          passed ? 'RW15_SAME_GID_OPENED' : 'RW15_SAME_GID_FAILED',
          passed
            ? `Both issuers hashed the exact bytes "${ALICE_GID}". Their zero-share terms cancel under the LSSS reconstruction, so the recovered GT element authenticates the record.`
            : 'The live recovered element or authenticated record did not match the encryptor’s value.',
          {
            'data-rw15-case': 'same-gid',
            'data-policy-satisfied': 'true',
            'data-aead-accepted': String(opened.ok),
            'data-recovered-matches': String(matches),
          },
          facts([
            el('span', {}, 'Exact canonical GID: ', el('code', { text: ALICE_GID }), '.'),
            el('span', {}, 'Selected rows: ', el('code', { text: result.reconstruction.usedRows.join(', ') }), '.'),
            pairingFact(result.reconstruction.usedRows.length, result.pairings),
            gtFingerprint('Expected GT', this.crossFixture.shared),
            gtFingerprint('Recovered GT', result.recovered),
            opened.ok
              ? el('span', {}, 'Authenticated plaintext: ', el('code', { text: opened.plaintext }))
              : el('span', {}, 'Record result: ', codeTag(opened.code)),
          ]),
        ),
      );
    } finally {
      this.endAction();
    }
  }

  private async runCrossGid(): Promise<void> {
    if (!this.initialized || this.busy || !this.keys || !this.crossFixture) return;
    this.beginAction(this.crossGidHost, 'Evaluating raw cross-user row terms');
    try {
      const result = rwRawDecrypt(this.crossFixture.ciphertext, [
        { rowIndex: 1, key: this.keys.bobDoctor, pairingGid: BOB_GID },
        { rowIndex: 2, key: this.keys.eveCardiology, pairingGid: EVE_GID },
      ]);
      if (!result.ok) {
        clear(this.crossGidHost);
        this.crossGidHost.appendChild(
          outcomeBox(
            'fail',
            'Raw labels did not satisfy the fixture',
            result.code,
            'This fixture is supposed to reach the cryptographic combination; an early policy failure is not the demonstrated collusion result.',
            {
              'data-rw15-case': 'cross-gid',
              'data-policy-satisfied': 'false',
              'data-aead-accepted': 'false',
              'data-recovered-matches': 'false',
            },
          ),
        );
        return;
      }
      const matches = gtEquals(result.recovered, this.crossFixture.shared);
      const opened = await rwOpenRecord(result.recovered, this.crossFixture.sealed);
      const resisted = !matches && !opened.ok;
      clear(this.crossGidHost);
      this.crossGidHost.appendChild(
        outcomeBox(
          resisted ? 'warn' : 'fail',
          resisted ? 'Labels satisfy; cross-GID cryptography rejects' : 'Unexpected cross-GID acceptance',
          resisted ? 'RW15_CROSS_GID_TAG_REJECTED' : 'RW15_CROSS_GID_ACCEPTED',
          resisted
            ? 'The raw pool reaches both LSSS rows, but zero-share terms do not cancel under different H(GID) bases. The combiner recovers the wrong GT element and AES-GCM rejects its derived key.'
            : 'The raw cross-user pool unexpectedly matched the encapsulated target or authenticated the record.',
          {
            'data-rw15-case': 'cross-gid',
            'data-policy-satisfied': 'true',
            'data-aead-accepted': String(opened.ok),
            'data-recovered-matches': String(matches),
          },
          facts([
            el(
              'span',
              {},
              'Row 1: ',
              el('code', { text: `${DOCTOR} / ${BOB_GID}` }),
              '; row 2: ',
              el('code', { text: `${CARDIOLOGY} / ${EVE_GID}` }),
              '.',
            ),
            el('span', {}, 'Structural reconstruction: ', el('strong', { text: 'satisfied' }), '.'),
            pairingFact(result.reconstruction.usedRows.length, result.pairings),
            gtFingerprint('Expected GT', this.crossFixture.shared),
            gtFingerprint('Raw recovered GT', result.recovered),
            el(
              'span',
              {},
              'AEAD result: ',
              opened.ok ? codeTag('UNEXPECTED_OPEN') : codeTag(opened.code),
              '. The API did not reject a GID mismatch before doing the algebra.',
            ),
          ]),
        ),
      );
    } finally {
      this.endAction();
    }
  }

  private async runCompromise(): Promise<void> {
    if (
      !this.initialized ||
      this.busy ||
      !this.hospital ||
      !this.crossFixture ||
      !this.hospitalFixture
    ) return;
    this.beginAction(this.compromiseHost, 'Using the compromised Hospital master secret');
    try {
      const forged = rwKeygen(
        this.hospital.sk,
        MALLORY_GID,
        DOCTOR,
        secureRandom,
        'compromised-hospital-mallory',
      ).key;
      const hospitalResult = rwDecrypt(this.hospitalFixture.ciphertext, MALLORY_GID, [forged]);
      const crossResult = rwDecrypt(this.crossFixture.ciphertext, MALLORY_GID, [forged]);
      const hospitalOpen = hospitalResult.ok
        ? await rwOpenRecord(hospitalResult.recovered, this.hospitalFixture.sealed)
        : null;
      const ownPolicyBroken = hospitalResult.ok && hospitalOpen?.ok === true;
      const boardStillRequired = !crossResult.ok && crossResult.code === 'POLICY_UNSATISFIED';
      const expected = ownPolicyBroken && boardStillRequired;
      const forgedFp = await keyFingerprint(forged);

      clear(this.compromiseHost);
      this.compromiseHost.appendChild(
        outcomeBox(
          expected ? 'warn' : 'fail',
          expected ? 'Hospital-only policy lost; Board remains independent' : 'Compromise boundary differed from the model',
          expected ? 'RW15_ONE_AUTHORITY_COMPROMISED' : 'RW15_COMPROMISE_FIXTURE_FAILED',
          expected
            ? 'Hospital can mint any Hospital-controlled attribute for any GID. It still lacks Board’s master secret, so the cross-authority AND remains unsatisfied for Mallory.'
            : 'One or both executable compromise checks did not produce the expected boundary.',
          {
            'data-rw15-case': 'compromise',
            'data-own-policy-opened': String(ownPolicyBroken),
            'data-cross-policy-opened': String(crossResult.ok),
            'data-board-still-required': String(boardStillRequired),
          },
          facts([
            el(
              'span',
              {},
              'Minted component: ',
              el('code', { text: `${DOCTOR} / ${MALLORY_GID}` }),
              '; SHA-256 ',
              el('code', { text: shortHex(forgedFp, 16, 12) }),
              '.',
            ),
            el(
              'span',
              { attrs: { 'data-compromise-policy': 'authority-a-only', 'data-opened': String(ownPolicyBroken) } },
              'Hospital-only policy: ',
              statusChip(ownPolicyBroken ? 'fail' : 'pass', ownPolicyBroken ? 'opened by compromised issuer' : 'not opened'),
              '.',
            ),
            el(
              'span',
              { attrs: { 'data-compromise-policy': 'cross-authority', 'data-opened': String(crossResult.ok) } },
              'Hospital AND Board policy: ',
              statusChip(boardStillRequired ? 'pass' : 'fail', boardStillRequired ? 'Board still required' : 'unexpectedly satisfied'),
              '.',
            ),
            hospitalResult.ok
              ? pairingFact(hospitalResult.reconstruction.usedRows.length, hospitalResult.pairings)
              : el('span', { text: 'Hospital-only decryption performed no row combination.' }),
          ]),
        ),
      );
    } finally {
      this.endAction();
    }
  }

  private repeatedAttributeDisclosure(): HTMLDetailsElement {
    const fixture = repeatedAttributeFixture();
    const table = el('table');
    table.appendChild(
      el('caption', {
        text: 'Actual RW15 compiler rows for the repeated-attribute policy',
      }),
    );
    table.appendChild(
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { text: 'Row' }),
          el('th', { text: 'Authority-qualified attribute' }),
          el('th', { text: 'LSSS vector' }),
          el('th', { text: 'Selected by one STUDENT@UT key' }),
        ),
      ),
    );
    const body = el('tbody');
    for (const row of fixture.lsss.rows) {
      const selected = fixture.usedRows.includes(row.index);
      body.appendChild(
        el(
          'tr',
          {
            attrs: {
              'data-rw15-repeat-row': String(row.index),
              'data-selected': String(selected),
            },
          },
          el('th', { attrs: { scope: 'row' }, text: String(row.index) }),
          el('td', {}, el('code', { text: row.attribute })),
          el('td', {}, el('code', { text: `[${row.vector.join(', ')}]` })),
          el('td', {}, statusChip(selected ? 'pass' : 'neutral', selected ? 'yes' : 'no')),
        ),
      );
    }
    table.appendChild(body);

    const block = disclosure(
      'Repeated attributes: one logical key can serve two rows',
      el(
        'p',
        {},
        'The authors’ policy ',
        el('code', { text: '(STUDENT@UT OR PROFESSOR@OU) AND (STUDENT@UT OR MASTERS@OU)' }),
        ' contains ',
        el('code', { text: 'STUDENT@UT' }),
        ' twice. The compiler preserves that exact logical label. A held set containing one ',
        el('code', { text: 'STUDENT@UT' }),
        ' key reconstructs with rows ',
        el('code', { text: fixture.usedRows.join(', ') }),
        '; it does not invent occurrence labels such as ',
        el('code', { text: 'STUDENT@UT:1' }),
        ' or ',
        el('code', { text: 'STUDENT@UT:2' }),
        '.',
      ),
      scroller('RW15 repeated-attribute LSSS rows', table),
    );
    block.setAttribute('data-rw15-repeat-satisfied', String(fixture.satisfied));
    block.setAttribute('data-rw15-repeat-used-rows', fixture.usedRows.join(','));
    return block;
  }

  private constructionDisclosure(): HTMLDetailsElement {
    const block = disclosure(
      'Construction equation, proof scope, and deployment assumptions',
      el(
        'p',
        {},
        'For selected row x, this implementation evaluates the RW15 row term below. ',
        el('code', { text: 'C1,x' }),
        ' is already in GT, so each selected row has three pairing terms—not four.',
      ),
      formula(
        'RW15 row and reconstruction equations',
        [
          'T_x = C1,x · e(C2,x, K_GID,δ(x)) · e(C3,x, H(GID)) · e(K′_GID,δ(x), C4,x)',
          'M   = C0 / ∏_(x∈I) T_x^γ_x',
          '',
          'H(GID), F(attribute), K, C4 ∈ G2',
          'Y, K′, C2, C3 ∈ G1; C0, C1, M ∈ GT',
        ].join('\n'),
      ),
      el(
        'p',
        {},
        'RW15 proves ',
        el('strong', { text: 'static (non-adaptive) security in the random-oracle model under q-DPBDHE2' }),
        ' for a challenge matrix of at most q × q. The policy is a public monotone LSSS. See ',
        el(
          'a',
          {
            text: 'Rouselakis–Waters, FC 2015, §4.1',
            attrs: { href: PAPER_URL, target: '_blank', rel: 'noreferrer' },
          },
        ),
        ' and the ',
        el(
          'a',
          {
            text: 'authors’ asymmetric Charm implementation',
            attrs: { href: IMPLEMENTATION_URL, target: '_blank', rel: 'noreferrer' },
          },
        ),
        '.',
      ),
      el(
        'ul',
        { class: 'honesty-list' },
        el(
          'li',
          { attrs: { 'data-rw15-assumption': 'authority-directory' } },
          'External deployment assumption: an authenticated directory binds each authority public key to its controlled namespace.',
        ),
        el(
          'li',
          { attrs: { 'data-rw15-assumption': 'gid-proofing' } },
          'External deployment assumption: every issuer proof-checks the subject and uses the same byte-exact canonical GID. The cryptography binds a supplied GID; it does not prove a civil identity.',
        ),
        el(
          'li',
          { attrs: { 'data-rw15-nonclaim': 'hybrid-wrapper' } },
          'The canonical encodings and HKDF-SHA-256/AES-256-GCM record wrapper are this lab’s executable teaching profile. The RW15 proof is not transferred to that hybrid composition.',
        ),
        el(
          'li',
          { attrs: { 'data-rw15-nonclaim': 'security-properties' } },
          'The theorem allows statically declared corrupt authorities under its challenge restriction. This page exercises the narrower case of exposing one honestly generated authority secret; it does not test rogue-key registration, malformed or equivocal issuance, adaptive corruption, or authority-directory compromise. No adaptive-security, standard-model, CCA-security, sender-authentication, policy-privacy, revocation, side-channel, or production-hardening claim is made.',
        ),
      ),
    );
    block.setAttribute('data-rw15-claim-scope', 'static-rom-q-dpbdhe2');
    return block;
  }

  private beginAction(host: HTMLElement, label: string): void {
    this.busy = true;
    this.setControlsDisabled(true);
    this.element.setAttribute('aria-busy', 'true');
    clear(host);
    host.appendChild(statusChip('neutral', label));
  }

  private endAction(): void {
    this.busy = false;
    this.setControlsDisabled(false);
    this.element.removeAttribute('aria-busy');
  }

  private setControlsDisabled(disabled: boolean): void {
    this.sameGidButton.disabled = disabled;
    this.crossGidButton.disabled = disabled;
    this.compromiseButton.disabled = disabled;
  }

  private renderUnexpected(error: unknown, host: HTMLElement): void {
    clear(host);
    host.appendChild(
      outcomeBox(
        'fail',
        'RW15 lesson error',
        'RW15_LESSON_ERROR',
        error instanceof Error ? error.message : 'An unexpected RW15 lesson error occurred.',
        { 'data-rw15-unexpected': 'true' },
      ),
    );
    this.busy = false;
    this.element.removeAttribute('aria-busy');
    this.setControlsDisabled(!this.initialized);
  }
}

export function createRw15Lesson(): Rw15Lesson {
  return new Rw15Lesson();
}
