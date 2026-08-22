/**
 * The page.
 *
 * One live lab -- one authority, one staff list, one attribute registry, one
 * sealed envelope -- driven by seven exhibits. Everything the page prints came
 * out of the real scheme in src/fame; nothing is staged.
 */
import { gtToHex, ORDER } from '../fame/bls';
import { FAILURE_CODES, FAILURE_CODE_IDS } from '../fame/codes';
import { deriveAesKey, HKDF_INFO, HKDF_SALT, toHex } from '../fame/kem';
import { policyToMsp, reconstruct, type Msp } from '../fame/msp';
import {
  PRESETS,
  addLeaf,
  attr,
  formatPolicy,
  or,
  PolicyError,
  removeLeaf,
  setAttributeName,
  setThreshold,
  wrapLeafInGate,
  type PolicyNode,
  type ThresholdNode,
} from '../fame/policy';
import {
  ATTRIBUTE_UNIVERSE,
  attemptCollusion,
  attemptOpen,
  createLab,
  escrowOpen,
  issueAll,
  issueKey,
  observePolicy,
  rowCoverage,
  sealUnder,
  staleAttributes,
  type Attempt,
  type Envelope,
  type LabState,
} from '../fame/system';
import {
  append,
  button,
  clear,
  disclosure,
  el,
  formula,
  icon,
  liveRegion,
  scroller,
  section,
  select,
  statusChip,
  type Child,
} from './dom';
import {
  playStages,
  renderLedger,
  renderMatrix,
  renderPeople,
  renderPipeline,
  renderReconstruction,
  renderResidual,
  renderTransform,
  renderTree,
  renderVerdict,
  type PersonView,
  type Stage,
} from './views';

const DEFAULT_RECORD =
  'PATIENT 00-4417 · Ward 3B · Troponin I 0.42 ng/mL · ECG: ST elevation, leads V2-V4';

export class App {
  private lab: LabState;
  private policy: PolicyNode;
  private msp: Msp;
  private envelope: Envelope | null = null;
  private aesKeyHex: string | null = null;
  private record = DEFAULT_RECORD;
  private lastAttempt: Attempt | null = null;
  private reconstructionFor = 'Alice';

  private readonly hosts: Record<string, HTMLElement> = {};

  constructor(private readonly root: HTMLElement) {
    this.lab = createLab();
    this.policy = PRESETS[0].build();
    this.msp = policyToMsp(this.policy);
    observePolicy(this.lab, this.policy);
    issueAll(this.lab);
  }

  /* ---------------------------------------------------------------- mount */

  async mount(): Promise<void> {
    clear(this.root);
    this.root.appendChild(this.intro());
    this.root.appendChild(this.builderPanel());
    this.root.appendChild(this.matrixPanel());
    this.root.appendChild(this.accessPanel());
    this.root.appendChild(this.reconstructionPanel());
    this.root.appendChild(this.collusionPanel());
    this.root.appendChild(this.escrowPanel());
    this.root.appendChild(this.revocationPanel());
    this.root.appendChild(this.honestyPanel());
    this.root.appendChild(this.codesPanel());
    await this.seal();
  }

  private host(name: string, cls = ''): HTMLElement {
    const node = el('div', { class: cls, attrs: { 'data-host': name } });
    this.hosts[name] = node;
    return node;
  }

  /**
   * A host that announces itself. Every result on this page is produced by
   * something the reader did, so each one lands in a polite live region rather
   * than appearing silently for a screen-reader user.
   */
  private hostLive(name: string, label: string): HTMLElement {
    const node = liveRegion(label);
    node.setAttribute('data-host', name);
    this.hosts[name] = node;
    return node;
  }

  private refresh(name: string, ...children: Child[]): void {
    const node = this.hosts[name];
    if (!node) return;
    clear(node);
    append(node, children);
  }

  /* ----------------------------------------------------------------- intro */

  private intro(): HTMLElement {
    return el(
      'div',
      { class: 'intro', attrs: { id: 'intro' } },
      el('h2', { text: 'What is attribute-based encryption?' }),
      el(
        'p',
        {},
        'Ordinary public-key encryption addresses a ',
        el('strong', { text: 'person' }),
        ': you pick a recipient and encrypt to their key. Attribute-based encryption addresses a ',
        el('strong', { text: 'rule' }),
        '. You encrypt to "a cardiologist, or anyone in the emergency department", and whoever turns out to hold those attributes can read it. Nobody has to know in advance who that will be.',
      ),
      el(
        'p',
        {},
        'The hard part is not writing the rule down. It is making sure two people cannot ',
        el('strong', { text: 'combine' }),
        ' their attributes. If a doctor and a cardiologist could pool their keys and read anything the pair jointly qualifies for, the rule would be decoration. Everything on this page exists to let you try that, against the real scheme, and watch it fail for a reason you can see.',
      ),
      el(
        'p',
        {},
        'The scheme is ',
        el('strong', { text: 'FAME' }),
        ' (Agrawal and Chase, ACM CCS 2017), running over BLS12-381 pairings in your browser. It is a teaching demo, not production cryptography: see the scoping panel near the bottom for exactly what it does and does not show.',
      ),
    );
  }

  /* --------------------------------------------------------------- builder */

  private builderPanel(): HTMLElement {
    const presetSelect = select(
      'Start from',
      PRESETS.map((p) => ({ value: p.id, label: p.label })),
      (id) => {
        const preset = PRESETS.find((p) => p.id === id);
        if (preset) void this.setPolicy(preset.build());
      },
      'preset',
      PRESETS[0].id,
    );

    const recordInput = el('input', {
      class: 'text-input',
      attrs: {
        id: 'record-input',
        type: 'text',
        value: this.record,
        maxlength: '160',
        spellcheck: 'false',
      },
      on: {
        input: (e) => {
          this.record = (e.target as HTMLInputElement).value;
          this.markUnsealed();
        },
      },
    });

    const customInput = el('input', {
      class: 'text-input',
      attrs: {
        id: 'custom-attr',
        type: 'text',
        placeholder: 'e.g. Radiology',
        maxlength: '60',
        spellcheck: 'false',
      },
    });
    const addCustom = button(
      'Add a custom attribute',
      () => void this.addCustomAttribute(customInput.value),
      'btn',
    );

    return section(
      {
        id: 'builder',
        number: '01',
        title: 'Compose a policy and seal a record under it',
        lede:
          'Build an access tree, then encapsulate a key under it. Change any gate or attribute and the policy is live immediately; the record has to be resealed, because a ciphertext is bound to the policy it was made for.',
      },
      el('div', { class: 'stack-row' }, presetSelect),
      this.host('preset-note', 'panel-lede'),
      this.host('tree'),
      el(
        'div',
        { class: 'stack-row' },
        el(
          'span',
          { class: 'field' },
          el('label', { class: 'field-label', text: 'Record to seal', attrs: { for: 'record-input' } }),
          recordInput,
        ),
      ),
      this.host('formula', 'panel-lede'),
      el(
        'div',
        { class: 'stack-row' },
        el(
          'span',
          { class: 'field' },
          el('label', {
            class: 'field-label',
            text: 'Custom attribute',
            attrs: { for: 'custom-attr' },
          }),
          customInput,
        ),
        addCustom,
      ),
      el('p', {
        class: 'panel-lede',
        text:
          'The attribute universe is unbounded -- FAME hashes attribute names rather than enrolling them -- so any string works. Not every string, though: the transform reserves the colon, and a name the scheme cannot label a row with is refused by name.',
      }),
      el(
        'div',
        { class: 'stack-row' },
        button('Seal the record under this policy', () => void this.seal(), 'btn btn-primary'),
      ),
      this.host('pipeline'),
      this.hostLive('seal-status', 'Sealing status'),
      disclosure(
        'Where the attribute-based part stops',
        el(
          'p',
          {},
          "FAME's message space is a single element of GT. A patient record does not fit in one, and splitting it into GT-sized pieces and encrypting each under the policy would be absurdly expensive. The paper says so plainly: ",
          el('em', {
            text:
              '"The standard method is to use a key encapsulation mechanism (KEM) wherein a random element of GT is ABE encrypted and hashed to derive a session key. This key is then used to encrypt the plaintext data through a fast symmetric key scheme like AES."',
          }),
        ),
        formula(
          'The hybrid pipeline, step by step',
          'K  <-- random element of GT\nct  = FAME.Encrypt(pk, policy, K)          <- the only attribute-based step\nk   = HKDF-SHA-256(serialize(K), salt, info)   576 bytes in, 32 out\nc   = AES-256-GCM(k, nonce, record, aad = policy string)',
        ),
        el('p', {}, `salt = "${HKDF_SALT}"`),
        el('p', {}, `info = "${HKDF_INFO}"`),
        el(
          'p',
          {},
          'The policy guards K. K guards the AES key. The AES key guards the record. Nothing about the record itself is attribute-based, and the AEAD is also what makes a wrong key visible: a bad decryption returns a perfectly well-formed group element, and it is the GCM tag that refuses. HPKE Envelope teaches the same KEM/KDF/AEAD shape with a Diffie-Hellman KEM in place of this one.',
        ),
      ),
      disclosure(
        'Why FAME and not the BSW07 access-tree scheme everybody cites',
        el(
          'p',
          {},
          'Bethencourt, Sahai and Waters (IEEE S&P 2007) is the classic ciphertext-policy construction, and it assumes a ',
          el('strong', { text: 'symmetric' }),
          ' pairing e : G0 x G0 -> GT. BLS12-381 is Type-3: e : G1 x G2 -> GT, with no efficient isomorphism in either direction. Several BSW elements are needed on both the key side and the ciphertext side, which is exactly where the symmetric assumption is load-bearing, so moving BSW onto this curve would require a translation argument for every one of them.',
        ),
        el(
          'p',
          {},
          'FAME was designed for Type-3 pairings from the start, so there is nothing to translate. The collusion property this page is built around is identical in both schemes -- per-user key randomization is what blocks pooling either way -- so nothing pedagogical is lost. Every group element the page shows is tagged G1 or G2, because getting that typing wrong is precisely the mistake FAME avoids.',
        ),
      ),
    );
  }

  /* ---------------------------------------------------------------- matrix */

  private matrixPanel(): HTMLElement {
    return section(
      {
        id: 'matrix',
        number: '02',
        title: 'The tree becomes a matrix',
        lede:
          'FAME never sees your tree. It sees a matrix M and a map pi from rows to attributes. A key opens the ciphertext exactly when the rows it owns combine to (1, 0, ..., 0). Most explanations skip this step, and it is where the intuition lives.',
      },
      el('h3', { text: 'The one-use restriction, and the workaround' }),
      this.host('transform'),
      disclosure(
        "What the paper says, and why it costs you key size",
        el(
          'p',
          {},
          el('em', {
            text:
              '"our scheme requires the mapping pi in an MSP to be an injective function, i.e., no two rows should be mapped to the same attribute. [...] A common way of getting around this problem [...] is to have k copies of each attribute in the universe for some fixed k chosen at set-up. For example, ‘Title:Prof’ will be replaced by ‘Title:Prof:1’, ‘Title:Prof:2’, ..., ‘Title:Prof:k’. The downside of this transformation is that the size of keys grows by a factor of k; but note that the encryption and decryption time is not affected."',
          }),
        ),
        el(
          'p',
          {},
          'The transform is not policy-side only, and that is the half most implementations miss. If Doctor becomes Doctor:1 and Doctor:2, then every key entitled to Doctor must carry both, because issuance cannot know which row index a future policy will use. Watch the key sizes in exhibit 3 change when you pick the reuse preset.',
        ),
        el(
          'p',
          {},
          'The indexed copies are genuinely different attributes: they hash to different points of G1. Stripping the index before hashing would put the collision straight back.',
        ),
      ),
      el('h3', { text: 'The monotone span program' }),
      this.host('matrix'),
      disclosure(
        'How the matrix is built',
        el(
          'p',
          {},
          'Every gate is a k-of-n threshold gate: OR is 1-of-n, AND is n-of-n. A gate holding share lambda splits it with a random degree-(k-1) polynomial q, where q(0) = lambda, and gives child i the value q(i). In matrix terms the child inherits its parent row and appends (i, i^2, ..., i^(k-1)) in k-1 freshly allocated columns. An OR gate allocates nothing, because a constant polynomial hands every child the same share.',
        ),
        formula(
          'How a child row of a k-of-n gate is built',
          'child i of a k-of-n gate:   [ parent row | i^1  i^2  ...  i^(k-1) ]\nOR (k = 1):                 [ parent row ]                (no new column)\nAND over n (k = n):         adds n-1 columns',
        ),
        el(
          'p',
          {},
          'Lewko and Waters have a conversion for AND/OR formulas that keeps every entry in {-1, 0, 1} and always admits reconstruction coefficients of 0 or 1, which FAME likes because it removes every exponentiation from decryption. It has no general k-of-n gate. The paper grants the trade in its own footnote: with general threshold gates the matrix entries leave that range. This page takes the general construction and pays for it in exponentiations, so that the Lagrange step is visible rather than hidden behind a sum of ones.',
        ),
      ),
    );
  }

  /* ---------------------------------------------------------------- access */

  private accessPanel(): HTMLElement {
    return section(
      {
        id: 'access',
        number: '03',
        title: 'Issue keys, then try to open the record',
        lede:
          'Each person gets a key for the attributes they hold, expanded into every indexed copy the registry currently requires. Then try each one against the sealed record. The policy tree above highlights which gate or row stopped you.',
      },
      el('div', { class: 'stack-row' }, button('Re-issue every key', () => this.reissueAll(), 'btn')),
      this.host('people'),
      this.hostLive('attempt', 'Decryption attempt result'),
      disclosure(
        'What a key actually is',
        formula(
          'The three parts of a FAME secret key',
          "sk0  = ( h^(b1 r1),  h^(b2 r2),  h^(r1 + r2) )                       in G2\nsk_y = ( sk_y1, sk_y2, g^(-sigma_y) )                                in G1\n  sk_yt = H(y,1,t)^(b1 r1/a_t) H(y,2,t)^(b2 r2/a_t) H(y,3,t)^((r1+r2)/a_t) g^(sigma_y/a_t)\nsk'  = ( sk'_1, sk'_2, g^d3 g^(-sigma') )                            in G1\n  sk'_t = g^(d_t) H(0,1,1,t)^(b1 r1/a_t) H(0,1,2,t)^(b2 r2/a_t) H(0,1,3,t)^((r1+r2)/a_t) g^(sigma'/a_t)",
        ),
        el(
          'p',
          {},
          'r1 and r2 are drawn fresh on every call to KeyGen. That is the entire collusion argument: every component of a key is blinded with that key’s own Br = (b1 r1, b2 r2, r1 + r2), and the blinding only cancels against the sk0 from the same key.',
        ),
      ),
    );
  }

  /* -------------------------------------------------------- reconstruction */

  private reconstructionPanel(): HTMLElement {
    return section(
      {
        id: 'reconstruction',
        number: '04',
        title: 'Threshold gates and the Lagrange step',
        lede:
          'Set a gate to "2 of 3" in exhibit 1 and the reconstruction stops being a sum of ones. Pick a key below to see the interpolation the decryptor performs, and the linear combination recomputed from the matrix rows.',
      },
      el(
        'div',
        { class: 'stack-row' },
        select(
          'Reconstruct with',
          this.lab.people.map((p) => ({ value: p.name, label: `${p.name} (${p.attributes.join(', ')})` })),
          (name) => {
            this.reconstructionFor = name;
            this.refreshReconstruction();
          },
          'recon-who',
          this.reconstructionFor,
        ),
      ),
      this.host('reconstruction'),
    );
  }

  /* ------------------------------------------------------------- collusion */

  private collusionPanel(): HTMLElement {
    const names = (): { value: string; label: string }[] =>
      this.lab.people.map((p) => ({ value: p.name, label: `${p.name} (${p.attributes.join(', ')})` }));

    let first = 'Bob';
    let second = 'Eve';

    return section(
      {
        id: 'collusion',
        number: '05',
        title: 'Collusion: pool two keys and watch it fail anyway',
        lede:
          'Pick two people whose attributes JOINTLY satisfy the policy but who individually do not. Their key material is spliced into a single key -- the same type the decryptor takes -- and run through the real decryption. The policy check passes. The record stays shut.',
      },
      el(
        'div',
        { class: 'stack-row' },
        select('First holder', names(), (v) => (first = v), 'collude-a', first),
        select('Second holder', names(), (v) => (second = v), 'collude-b', second),
        button(
          'Pool the keys and decrypt',
          () => void this.runCollusion(first, second),
          'btn btn-primary',
        ),
      ),
      this.hostLive('collusion', 'Collusion attempt walkthrough'),
      disclosure(
        'The term that refuses to cancel',
        el(
          'p',
          {},
          'Work the exponents through the decryption equation for a key whose sk0 and sk’ came from holder A and whose component for row i came from holder o(i):',
        ),
        formula(
          'The leftover blinding factor',
          'recovered / message  =  prod_i prod_{l,t}  e( H(pi(i), l, t), h ) ^ ( gamma_i * s_t * (Br^A_l - Br^o(i)_l) )',
        ),
        el(
          'p',
          {},
          'Every factor with o(i) = A vanishes, because the difference in the exponent is zero. A coherent key therefore leaves exactly 1, and decryption is correct. A spliced key leaves the factors belonging to the borrowed rows, and they cannot vanish, because r is drawn fresh for every key issued. That is collusion resistance written as an equation, and the ledger above is that equation with the numbers filled in.',
        ),
        el(
          'p',
          {},
          'Nothing in FAME detected anything. There is no collusion check in the scheme and none was added here. Decryption ran to completion and returned a group element; it was simply the wrong one, and AES-GCM rejected the tag that followed from it.',
        ),
      ),
    );
  }

  /* ---------------------------------------------------------------- escrow */

  private escrowPanel(): HTMLElement {
    return section(
      {
        id: 'escrow',
        number: '06',
        title: 'The authority can read everything',
        lede:
          'The master secret is not itself a decryption key -- there is no function taking msk and a ciphertext to a plaintext. What msk grants is KeyGen for an arbitrary attribute set. So the authority mints itself a key that satisfies your policy, and then decrypts with it like anybody else. Two steps, shown separately, because collapsing them teaches the right conclusion by the wrong route.',
      },
      el(
        'div',
        { class: 'stack-row' },
        button('Mint an authority key, then decrypt', () => void this.runEscrow(), 'btn btn-primary'),
      ),
      this.hostLive('escrow', 'Authority escrow result'),
    );
  }

  /* ------------------------------------------------------------ revocation */

  private revocationPanel(): HTMLElement {
    let who = 'Bob';
    return section(
      {
        id: 'revocation',
        number: '07',
        title: 'There is no revocation',
        lede:
          'Revoking someone strikes them off the authority’s list. It does not touch their key, the public key, or any ciphertext. Revoke a holder, seal a brand-new record afterwards, and watch them open it.',
      },
      el(
        'div',
        { class: 'stack-row' },
        select(
          'Holder',
          this.lab.people.map((p) => ({ value: p.name, label: p.name })),
          (v) => (who = v),
          'revoke-who',
          who,
        ),
        button(
          'Revoke, seal a new record, then decrypt with the revoked key',
          () => void this.runRevocation(() => who),
          'btn btn-primary',
        ),
      ),
      this.hostLive('revocation', 'Revocation fixture result'),
      disclosure(
        'What it would take to actually revoke someone',
        el(
          'p',
          {},
          'Three options, none of them free. Re-run Setup and re-issue every key, which invalidates every existing ciphertext too. Add a time or epoch attribute to every policy and re-encrypt on each epoch, which turns revocation into a re-encryption schedule. Or use a scheme built with revocation in the construction, which costs you something else -- usually ciphertext size or a bound on the number of users.',
        ),
        el(
          'p',
          {},
          'An issued key decrypts matching ciphertexts indefinitely. That is a property of the scheme, not a gap in this implementation.',
        ),
      ),
    );
  }

  /* --------------------------------------------------------------- honesty */

  private honestyPanel(): HTMLElement {
    const item = (strong: string, rest: string): HTMLElement =>
      el('li', {}, el('strong', { text: `${strong} ` }), rest);

    return el(
      'div',
      { class: 'honesty', attrs: { id: 'honesty', role: 'group', 'aria-labelledby': 'honesty-h' } },
      el('h2', { text: 'What is real here, and what this does not prove', attrs: { id: 'honesty-h' } }),
      el(
        'p',
        {},
        el('strong', { text: 'Not production cryptography.' }),
        ' This is a teaching demo. Every key lives in this browser tab for as long as the tab is open and is never stored or transmitted.',
      ),
      el('h3', { text: 'Real' }),
      el(
        'ul',
        {},
        item(
          'The scheme.',
          'FAME exactly as published in Figure 3.1 of Agrawal and Chase, ACM CCS 2017, with the linear-assumption parameter k = 2, over BLS12-381 via @noble/curves. Setup, KeyGen, Encrypt and Decrypt are hand-written from the paper; only the field and curve arithmetic and RFC 9380 hash-to-curve are library code.',
        ),
        item(
          'The collusion failure.',
          'Two keys really are spliced into one and run through the same Decrypt every other key uses. The leftover blinding factor is computed twice, by two different routes, and the page shows both.',
        ),
        item(
          'The hybrid layer.',
          'HKDF-SHA-256 and AES-256-GCM from WebCrypto. The tag rejection you see is a real authentication failure.',
        ),
        item(
          'The one-use transform.',
          'Applied to policies and to keys, with the factor-of-k key growth the paper describes shown as a count.',
        ),
      ),
      el('h3', { text: 'Not proved by anything on this page' }),
      el(
        'ul',
        {},
        item(
          'That FAME is secure.',
          'Watching one splicing attack fail is a demonstration of the mechanism, not a security proof. The proof is in the paper, under a variant of the k-linear assumption in the random oracle model, and it rules out attacks this page never attempts.',
        ),
        item(
          'That your policy is the right policy.',
          'The scheme enforces the rule you wrote. It has no opinion about whether the rule is sensible.',
        ),
        item(
          'Anything about timing.',
          'Nothing here is constant-time and no side-channel claim is made. Pairings in JavaScript leak timing freely.',
        ),
        item(
          'That the authority is trustworthy.',
          'Exhibit 6 shows the opposite. Key escrow is inherent to single-authority ABE; multi-authority schemes exist and are a different construction.',
        ),
        item(
          'Revocation.',
          'Exhibit 7 shows there is none. An issued key keeps working forever.',
        ),
      ),
      el('h3', { text: 'Simplified, and named as such' }),
      el(
        'ul',
        {},
        item(
          'Generators.',
          'g and h are the standard BLS12-381 base points rather than freshly sampled generators. Both are public and any generator works; fixing them makes the pinned test vectors reproducible.',
        ),
        item(
          'Hash inputs.',
          "The paper writes H's arguments as a bare concatenation. This lab uses a length-prefixed, type-tagged encoding instead, because the indexed-copy transform makes the plain concatenation ambiguous: H(\"Doctor:1\" + \"1\" + \"1\") and H(\"Doctor:11\" + \"1\") would be the same input.",
        ),
        item(
          'k is not fixed at setup.',
          'The paper fixes the number of attribute copies at set-up. Here the registry raises it when a policy demands it, which is honest about the consequence -- keys issued under the old k become stale, and the page says so rather than silently re-issuing.',
        ),
      ),
    );
  }

  /* ----------------------------------------------------------------- codes */

  private codesPanel(): HTMLElement {
    const table = el('table');
    table.appendChild(
      el('caption', {
        text: 'Every outcome this lab can report. "internal" means an invariant that must never reach you as a verdict.',
      }),
    );
    table.appendChild(
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { text: 'Code' }),
          el('th', { text: 'Where it appears' }),
          el('th', { text: 'What it means' }),
        ),
      ),
    );
    const body = el('tbody');
    for (const id of FAILURE_CODE_IDS) {
      const code = FAILURE_CODES[id];
      body.appendChild(
        el(
          'tr',
          {},
          el('td', {}, el('span', { class: 'code-tag', text: code.id })),
          el(
            'td',
            {},
            code.surface === 'internal'
              ? statusChip('warn', 'internal')
              : statusChip('neutral', code.surface),
          ),
          el('td', { text: code.meaning }),
        ),
      );
    }
    table.appendChild(body);

    return section(
      {
        id: 'codes',
        number: '08',
        title: 'Failure codes',
        lede:
          'Every verdict on this page prints one of these identifiers verbatim, so a refusal always names its cause.',
      },
      scroller('Failure code reference', table),
    );
  }

  /* ------------------------------------------------------------- behaviour */

  /**
   * Adopt a new policy, or explain why it cannot be adopted.
   *
   * Two guards, and both are load bearing:
   *
   *  - A NO-OP EDIT CHANGES NOTHING. Re-selecting the preset already showing,
   *    or setting a gate to the k it already has, must not retire a verdict
   *    the reader just produced. The comparison is on the rendered formula
   *    rather than on object identity, because every preset build makes fresh
   *    node ids for the same tree.
   *
   *  - A REAL EDIT RETIRES EVERY RESULT ON THE PAGE. A ciphertext is bound to
   *    the policy it was made under, so an attempt, a collusion walkthrough,
   *    an escrow or a revocation fixture computed against the previous
   *    envelope is not merely out of date, it is about a different ciphertext.
   *    Leaving it on screen next to a new policy is the single most misleading
   *    thing this page could do.
   */
  private async setPolicy(next: PolicyNode): Promise<void> {
    try {
      const msp = policyToMsp(next);
      if (formatPolicy(next) === formatPolicy(this.policy)) return;
      this.policy = next;
      this.msp = msp;
    } catch (e) {
      if (e instanceof PolicyError) {
        this.refresh(
          'seal-status',
          el(
            'div',
            { class: 'verdict verdict-fail', attrs: { 'data-code': e.code } },
            el(
              'div',
              { class: 'verdict-head' },
              statusChip('fail', FAILURE_CODES[e.code].title),
              el('span', { class: 'code-tag', text: e.code }),
            ),
            el('p', { class: 'verdict-detail', text: e.message }),
          ),
        );
        return;
      }
      throw e;
    }
    observePolicy(this.lab, this.policy);
    this.envelope = null;
    this.aesKeyHex = null;
    this.lastAttempt = null;
    this.retireResults('the policy changed, so every result on this page was computed against a different ciphertext');
    this.renderAll();
    this.markUnsealed();
  }

  /**
   * Clear every result that belonged to the previous envelope, and say so.
   *
   * Hosts that were already empty stay empty: an untouched exhibit has nothing
   * to retire, and printing a retirement notice into one would claim a result
   * had existed.
   */
  private retireResults(reason: string): void {
    for (const name of ['attempt', 'collusion', 'escrow', 'revocation']) {
      const node = this.hosts[name];
      if (!node || node.childElementCount === 0) continue;
      clear(node);
      node.appendChild(
        el(
          'div',
          { class: 'verdict verdict-warn', attrs: { 'data-retired': 'true' } },
          el('div', { class: 'verdict-head' }, statusChip('warn', 'Result retired')),
          el('p', { class: 'verdict-detail', text: `Retired: ${reason}. Run it again.` }),
        ),
      );
    }
  }

  /**
   * Add a free-text attribute to the root gate.
   *
   * This is the only route to MALFORMED_POLICY on the page, and it exists on
   * purpose: the selects elsewhere are clamped so they cannot produce an
   * invalid tree, which would leave the fail-closed path unreachable and
   * therefore untested. Typing `Doctor:1` or a name with characters the row
   * labelling cannot carry gets refused by name rather than silently dropped.
   */
  private async addCustomAttribute(raw: string): Promise<void> {
    const name = raw.trim();
    const root = this.policy;
    const next =
      root.kind === 'threshold'
        ? addLeaf(root, root.id, name)
        : wrapLeafInGate(root, root.id, name);
    await this.setPolicy(next);
  }

  private markUnsealed(): void {
    this.refresh(
      'seal-status',
      el(
        'div',
        { class: 'verdict verdict-warn' },
        el(
          'div',
          { class: 'verdict-head' },
          statusChip('warn', 'Not sealed'),
        ),
        el('p', {
          class: 'verdict-detail',
          text: 'The policy or the record changed. A ciphertext is bound to the policy it was made under, so seal again before trying to open anything.',
        }),
      ),
    );
  }

  private async seal(): Promise<void> {
    this.retireResults('a new record was sealed, so the previous ciphertext no longer exists');
    this.envelope = await sealUnder(this.lab, this.policy, this.record);
    const { rawKey } = await deriveAesKey(this.envelope.witness.encapsulated);
    this.aesKeyHex = toHex(rawKey);
    this.lastAttempt = null;
    this.renderAll();
    this.refresh(
      'seal-status',
      el(
        'div',
        { class: 'verdict verdict-pass', attrs: { 'data-sealed': String(this.envelope.serial) } },
        el(
          'div',
          { class: 'verdict-head' },
          statusChip('pass', 'Sealed'),
          el('span', { class: 'code-tag', text: `envelope #${this.envelope.serial}` }),
        ),
        el('p', {
          class: 'verdict-detail',
          text: `Encapsulated a fresh GT element under ${this.envelope.expression}, derived a 256-bit AES key from it, and sealed ${this.envelope.sealed.ciphertext.length - 16} bytes of record plus a 16-byte tag.`,
        }),
        el('p', {
          class: 'verdict-detail',
          text: `Ciphertext: ${this.msp.rows.length} rows of three G1 elements, three G2 elements in ct0, and one GT element in ct'.`,
        }),
      ),
    );
  }

  private renderAll(): void {
    this.refresh(
      'tree',
      renderTree(
        this.policy,
        {
          universe: ATTRIBUTE_UNIVERSE,
          rowLabel: this.msp.transform.rowLabel,
          status: this.lastAttempt?.reconstruction.status,
          editable: true,
        },
        {
          onThreshold: (gate: ThresholdNode, k: number) =>
            void this.setPolicy(setThreshold(this.policy, gate.id, k)),
          onAttribute: (leafId, name) =>
            void this.setPolicy(setAttributeName(this.policy, leafId, name)),
          onRemove: (leafId) => void this.setPolicy(removeLeaf(this.policy, leafId)),
          onAdd: (gateId) => void this.setPolicy(addLeaf(this.policy, gateId, 'OnCall')),
          onSplit: (leafId) => void this.setPolicy(wrapLeafInGate(this.policy, leafId, 'OnCall')),
        },
      ),
    );
    this.refresh(
      'formula',
      el('span', {}, 'Current policy: '),
      el('code', { text: formatPolicy(this.policy) }),
    );
    const note = PRESETS.find((p) => formatPolicy(p.build()) === formatPolicy(this.policy));
    this.refresh('preset-note', note ? note.note : 'Edited policy.');
    this.refresh(
      'pipeline',
      renderPipeline(
        this.envelope,
        this.aesKeyHex,
        this.envelope ? gtToHex(this.envelope.witness.encapsulated) : null,
      ),
    );
    this.refresh('transform', renderTransform(this.msp.transform, this.lab.registry.snapshot()));
    this.refreshMatrix();
    this.refreshPeople();
    this.refreshReconstruction();
  }

  private refreshMatrix(): void {
    const key = this.lastAttempt ? this.lab.keys.get(this.lastAttempt.who) : undefined;
    const coverage =
      key && this.envelope ? rowCoverage(this.envelope, key) : undefined;
    this.refresh('matrix', renderMatrix(this.msp, coverage, this.lastAttempt?.reconstruction));
  }

  private refreshPeople(): void {
    const views: PersonView[] = this.lab.people.map((p) => {
      const key = this.lab.keys.get(p.name);
      return {
        name: p.name,
        attributes: p.attributes,
        revoked: p.revoked,
        key,
        stale: key ? staleAttributes(this.lab, key) : [],
      };
    });
    this.refresh(
      'people',
      renderPeople(
        views,
        (name) => void this.runAttempt(name),
        (name) => this.toggleRevoked(name),
        (name) => this.reissue(name),
        this.envelope !== null,
      ),
    );
  }

  private refreshReconstruction(): void {
    const key = this.lab.keys.get(this.reconstructionFor);
    if (!key) {
      this.refresh('reconstruction', el('p', { text: 'No key issued for that holder yet.' }));
      return;
    }
    const rec = reconstruct(this.policy, this.msp, new Set(key.issued.key.labels));
    this.refresh(
      'reconstruction',
      el(
        'p',
        { class: 'verdict-detail' },
        `${this.reconstructionFor} holds `,
        el('code', { text: key.issued.key.labels.join(' , ') }),
        '. ',
        rec.satisfied
          ? statusChip('pass', 'satisfies the policy')
          : statusChip('fail', 'does not satisfy the policy'),
      ),
      renderReconstruction(this.msp, rec),
    );
  }

  private async runAttempt(name: string): Promise<void> {
    const key = this.lab.keys.get(name);
    if (!key || !this.envelope) return;
    const attempt = await attemptOpen(this.envelope, key);
    this.lastAttempt = attempt;
    this.refresh('attempt', renderVerdict(attempt));
    this.refreshMatrix();
    this.refresh(
      'tree',
      renderTree(
        this.policy,
        {
          universe: ATTRIBUTE_UNIVERSE,
          rowLabel: this.msp.transform.rowLabel,
          status: attempt.reconstruction.status,
          editable: true,
        },
        {
          onThreshold: (gate, k) => void this.setPolicy(setThreshold(this.policy, gate.id, k)),
          onAttribute: (leafId, n) => void this.setPolicy(setAttributeName(this.policy, leafId, n)),
          onRemove: (leafId) => void this.setPolicy(removeLeaf(this.policy, leafId)),
          onAdd: (gateId) => void this.setPolicy(addLeaf(this.policy, gateId, 'OnCall')),
          onSplit: (leafId) => void this.setPolicy(wrapLeafInGate(this.policy, leafId, 'OnCall')),
        },
      ),
    );
  }

  private reissue(name: string): void {
    const person = this.lab.people.find((p) => p.name === name);
    if (!person) return;
    issueKey(this.lab, person);
    this.refreshPeople();
    this.refreshReconstruction();
  }

  private reissueAll(): void {
    issueAll(this.lab);
    this.refreshPeople();
    this.refreshReconstruction();
  }

  private toggleRevoked(name: string): void {
    const person = this.lab.people.find((p) => p.name === name);
    if (!person) return;
    person.revoked = !person.revoked;
    this.refreshPeople();
  }

  private async runCollusion(a: string, b: string): Promise<void> {
    const host = this.hosts.collusion;
    const ka = this.lab.keys.get(a);
    const kb = this.lab.keys.get(b);
    if (!host || !ka || !kb || !this.envelope) return;

    if (a === b) {
      this.refresh(
        'collusion',
        el('p', {
          class: 'verdict-detail',
          text: 'Pick two different holders. Pooling a key with itself is just that key.',
        }),
      );
      return;
    }

    const outcomes = await attemptCollusion(this.lab, this.envelope, ka, kb);
    const soloA = await attemptOpen(this.envelope, ka);
    const soloB = await attemptOpen(this.envelope, kb);

    // A collusion scenario is a specific thing: NEITHER holder satisfies the
    // policy alone, and their union does. If either already qualifies there is
    // nothing to pool, and if the union still does not qualify the refusal
    // comes from the policy check rather than from collusion resistance.
    // Narrating "the blinding does not cancel" over either of those would be
    // asserting the lesson instead of showing it.
    const eitherQualifiesAlone = soloA.outcome === 'opened' || soloB.outcome === 'opened';
    const unionQualifies = outcomes.some((o) => o.analysis.satisfiedPolicy);

    if (eitherQualifiesAlone || !unionQualifies) {
      this.refresh(
        'collusion',
        el(
          'div',
          { class: 'verdict verdict-warn', attrs: { 'data-scenario': 'not-collusion' } },
          el('div', { class: 'verdict-head' }, statusChip('warn', 'Not a collusion scenario')),
          el('p', {
            class: 'verdict-detail',
            text: eitherQualifiesAlone
              ? `${soloA.outcome === 'opened' ? a : b} already satisfies this policy alone, so pooling adds nothing. Collusion means two holders who each fail and who jointly qualify -- pick a pair like that, or change the policy so neither one qualifies on their own.`
              : `${a} and ${b} do not satisfy this policy even between them, so the pooled key is refused by the policy check. That is the ordinary ATTR_MISSING path from exhibit 3, not collusion resistance.`,
          }),
          el('h4', { text: 'What each key does on its own' }),
          renderVerdict(soloA),
          renderVerdict(soloB),
          el('h4', { text: 'And pooled, in both splice directions' }),
          ...outcomes.map((o) => renderVerdict(o.attempt)),
        ),
      );
      return;
    }

    // In a genuine collusion scenario every splice direction is blocked: a
    // direction that opened would mean the base holder's own rows satisfied
    // the policy, which the check above has ruled out.
    const primary = outcomes[0];
    const other = outcomes[1];

    const stages: Stage[] = [
      {
        title: 'Alone, neither can open it',
        body: `${a}: ${soloA.code}. ${b}: ${soloB.code}. Each key satisfies only part of the policy.`,
        // Both are refusals by construction: the guard above returned early
        // if either holder qualified alone, and the compiler has narrowed
        // `outcome` to 'denied' | 'blocked' here to prove it.
        extra: el(
          'div',
          { class: 'stack-row' },
          statusChip('fail', `${a}: ${soloA.headline}`),
          statusChip('fail', `${b}: ${soloB.headline}`),
        ),
      },
      {
        title: 'Splice the two keys into one',
        body: `sk0 and sk' are taken from ${primary.pooled.baseHolder}; each attribute component is taken from whichever key has it. The result has the same type the decryptor accepts, and Decrypt cannot tell the difference.`,
        extra: el(
          'ul',
          { class: 'honesty-list' },
          ...[...primary.pooled.provenance].map(([label, holder]) =>
            el('li', {}, el('code', { text: label }), ` from ${holder}`),
          ),
        ),
      },
      {
        title: 'The policy check passes',
        tone: 'surprise',
        body: `The pooled attribute set satisfies ${this.envelope.expression}. There are valid reconstruction coefficients, so decryption runs all the way to the end. This is the part that surprises people: nothing rejects the key.`,
        extra: statusChip('warn', 'POLICY SATISFIED', 'and that is not enough'),
      },
      {
        title: 'The blinding does not cancel',
        tone: 'final',
        body: 'Every key carries its own Br = (b1 r1, b2 r2, r1 + r2). The numerator can only cancel the Br of the key sk0 came from. Rows borrowed from the other key leave their difference behind.',
        extra: renderLedger(primary.analysis),
      },
      {
        title: 'Two routes to the leftover factor, and they agree',
        tone: 'final',
        body: 'If the two agree, the ledger above is not a story about the failure. It is the failure, with the numbers in it.',
        extra: renderResidual(primary.analysis, (x) => gtToHex(x as never)),
      },
      {
        title: 'So the record stays shut',
        tone: 'final',
        body: `Both splice directions were tried. ${primary.attempt.who}: ${primary.attempt.code}. ${other.attempt.who}: ${other.attempt.code}.`,
        extra: el(
          'div',
          {},
          renderVerdict(primary.attempt),
          renderVerdict(other.attempt),
        ),
      },
    ];

    playStages(host, stages);
  }

  private async runEscrow(): Promise<void> {
    if (!this.envelope) return;
    const outcome = await escrowOpen(this.lab, this.envelope);
    this.refresh(
      'escrow',
      el(
        'div',
        { class: 'stage stage-surprise', attrs: { 'data-stage': '1' } },
        el('h4', { text: '1. Mint a key. This is all msk can do.' }),
        el('p', {
          text: `The authority chose an attribute set that satisfies ${this.envelope.expression} and ran KeyGen on it, exactly as it would for a member of staff. No ciphertext was involved.`,
        }),
        el(
          'p',
          {},
          'Minted for: ',
          el('code', { text: outcome.mintedLabels.join(' , ') }),
          ` — ${outcome.keyElements} group elements.`,
        ),
      ),
      el(
        'div',
        { class: 'stage stage-final', attrs: { 'data-stage': '2' } },
        el('h4', { text: '2. Decrypt with it, like any other key.' }),
        el('p', {
          text: 'The same Decrypt every holder uses. Nothing about this step knows the key belongs to the authority.',
        }),
        renderVerdict(outcome.attempt),
      ),
      el('p', {
        class: 'verdict-detail',
        text: 'The authority can therefore read every ciphertext under this public key, past and future. That is inherent to single-authority attribute-based encryption, exactly as it is to identity-based encryption. Multi-authority ABE splits the power across issuers; it is a different construction, not a setting.',
      }),
    );
  }

  private async runRevocation(who: () => string): Promise<void> {
    const name = who();
    const person = this.lab.people.find((p) => p.name === name);
    const key = this.lab.keys.get(name);
    if (!person || !key) return;

    person.revoked = true;
    this.refreshPeople();

    // The claim under test is about TIMING -- a key issued before a revocation
    // still opens a ciphertext created after it -- so the fixture needs a
    // ciphertext this holder can open. If the policy on screen does not admit
    // them at all, sealing under it would produce a POLICY_UNSATISFIED verdict
    // beside a heading claiming the opposite, which is worse than no exhibit.
    // So: use the live policy when it admits them, and otherwise seal under a
    // policy built from their own attributes, and say which was used.
    const admits = reconstruct(
      this.policy,
      this.msp,
      new Set(key.issued.key.labels),
    ).satisfied;
    const fixturePolicy = admits
      ? this.policy
      : or(person.attributes.map((a) => attr(a)));
    const usedPolicy = formatPolicy(fixturePolicy);
    if (!admits) observePolicy(this.lab, fixturePolicy);

    const fresh = await sealUnder(
      this.lab,
      fixturePolicy,
      `Sealed after ${name} was revoked · ${this.record}`,
    );
    const attempt = await attemptOpen(fresh, key);
    const opened = attempt.outcome === 'opened';

    this.refresh(
      'revocation',
      el(
        'div',
        { class: 'stage stage-surprise', attrs: { 'data-stage': '1' } },
        el('h4', { text: `1. ${name} is revoked` }),
        el('p', {
          text: `A boolean flipped on the authority's staff list. ${name}'s key is byte-for-byte what it was: ${key.issued.key.labels.join(', ')}, ${key.elements} group elements.`,
        }),
      ),
      el(
        'div',
        { class: 'stage', attrs: { 'data-stage': '2' } },
        el('h4', { text: '2. A brand-new record is sealed AFTER the revocation' }),
        el('p', {
          text: `Envelope #${fresh.serial}, under ${usedPolicy}, using the same public key. Nothing about the setup changed, because nothing about the setup could change without invalidating every other key too.`,
        }),
        admits
          ? null
          : el('p', {
              text: `The policy in exhibit 1 does not admit ${name} at all, so this fixture seals under a policy their attributes do satisfy. What is being shown is the timing, not the policy.`,
            }),
      ),
      el(
        'div',
        { class: `stage stage-final`, attrs: { 'data-stage': '3', 'data-opened': String(opened) } },
        el('h4', {
          text: opened
            ? '3. The revoked key opens it'
            : `3. The revoked key was refused -- but for the wrong reason (${attempt.code})`,
        }),
        renderVerdict(attempt),
      ),
      el(
        'p',
        { class: 'verdict-detail' },
        icon('warn', 'chip-icon'),
        ' An issued key decrypts matching ciphertexts indefinitely. These constructions provide no revocation, and this fixture is the evidence rather than the assertion.',
      ),
    );
  }
}

/** Exposed for the reconstruction panel's field rendering. */
export const FIELD_ORDER = ORDER;
