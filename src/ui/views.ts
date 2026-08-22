/**
 * Pure renderers. Each takes data and returns a detached element; none of them
 * reach into application state or listen for anything except the callbacks
 * they are handed.
 */
import { ORDER } from '../fame/bls';
import type { CollusionAnalysis } from '../fame/collusion';
import { GCM_NONCE_BYTES, GCM_TAG_BYTES, HKDF_INFO, toHex } from '../fame/kem';
import type { Msp, NodeStatus, Reconstruction } from '../fame/msp';
import { combineRows, isTargetVector } from '../fame/msp';
import type { OneUseTransform } from '../fame/oneuse';
import { gateLabel, type PolicyNode, type ThresholdNode } from '../fame/policy';
import type { Attempt, Envelope, KeyRecord } from '../fame/system';
import {
  append,
  button,
  clear,
  el,
  elementRef,
  fieldEntry,
  formula,
  icon,
  scroller,
  select,
  statusChip,
  type Child,
} from './dom';

/* -------------------------------------------------------------------------- */
/* Policy tree                                                                */
/* -------------------------------------------------------------------------- */

export interface TreeCallbacks {
  readonly onThreshold: (gate: ThresholdNode, k: number) => void;
  readonly onAttribute: (leafId: string, name: string) => void;
  readonly onRemove: (leafId: string) => void;
  readonly onAdd: (gateId: string) => void;
  readonly onSplit: (leafId: string) => void;
}

export interface TreeOptions {
  readonly universe: readonly string[];
  readonly rowLabel: ReadonlyMap<string, string>;
  readonly status?: ReadonlyMap<string, NodeStatus>;
  readonly editable: boolean;
}

/**
 * The access tree, editable in place.
 *
 * The gate selector is the "switch a node to 2-of-3" control: OR is 1-of-n and
 * AND is n-of-n, so a threshold is not a special case bolted on, it is the
 * general gate the other two are corners of.
 */
export function renderTree(
  root: PolicyNode,
  opts: TreeOptions,
  cb: TreeCallbacks,
): HTMLElement {
  let seq = 0;

  const nodeStatusClass = (id: string): string => {
    const s = opts.status?.get(id);
    if (!s) return '';
    return s.satisfied ? ' node-sat' : ' node-unsat';
  };

  const statusBadge = (id: string): Child => {
    const s = opts.status?.get(id);
    if (!s) return null;
    if (s.satisfied) return statusChip('pass', 'satisfied');
    if (s.reason === 'ATTR_MISSING') return statusChip('fail', 'ATTR_MISSING', s.missing);
    return statusChip('fail', 'THRESHOLD_NOT_MET', `${s.have} of ${s.need}`);
  };

  const renderNode = (node: PolicyNode, parent: ThresholdNode | null): HTMLLIElement => {
    seq += 1;
    const li = el('li');

    if (node.kind === 'attribute') {
      const label = opts.rowLabel.get(node.id);
      const body = el(
        'span',
        { class: `node${nodeStatusClass(node.id)}` },
        icon('key', 'chip-icon'),
        opts.editable
          ? select(
              'Attribute',
              opts.universe.map((n) => ({ value: n, label: n })),
              (v) => cb.onAttribute(node.id, v),
              `leaf-${node.id}`,
              node.name,
            )
          : el('span', { class: 'node-name', text: node.name }),
        label ? el('span', { class: 'node-label', text: `row label ${label}` }) : null,
        statusBadge(node.id),
      );
      if (opts.editable && parent && parent.children.length > 1) {
        body.appendChild(
          button(
            'Remove',
            () => cb.onRemove(node.id),
            'btn btn-small',
          ),
        );
      }
      if (opts.editable) {
        const split = button('Wrap in a gate', () => cb.onSplit(node.id), 'btn btn-small');
        split.setAttribute('aria-label', `Wrap ${node.name} in a new gate`);
        body.appendChild(split);
      }
      li.appendChild(body);
      return li;
    }

    const gate = node;
    const n = gate.children.length;
    const head = el(
      'span',
      { class: `node node-gate${nodeStatusClass(gate.id)}` },
      opts.editable
        ? select(
            'Gate',
            Array.from({ length: n }, (_, i) => ({
              value: String(i + 1),
              label:
                i + 1 === 1 && n > 1
                  ? `OR (1 of ${n})`
                  : i + 1 === n && n > 1
                    ? `AND (${n} of ${n})`
                    : `${i + 1} of ${n}`,
            })),
            (v) => cb.onThreshold(gate, Number(v)),
            `gate-${gate.id}`,
            String(gate.threshold),
          )
        : el('span', { class: 'node-name', text: gateLabel(gate) }),
      statusBadge(gate.id),
      opts.editable
        ? button('Add attribute', () => cb.onAdd(gate.id), 'btn btn-small')
        : null,
    );
    li.appendChild(head);

    const kids = el('ul');
    for (const child of gate.children) kids.appendChild(renderNode(child, gate));
    li.appendChild(kids);
    return li;
  };

  const list = el('ul', { class: 'tree' });
  list.appendChild(renderNode(root, null));
  return list;
}

/* -------------------------------------------------------------------------- */
/* One-use transform                                                          */
/* -------------------------------------------------------------------------- */

export function renderTransform(
  transform: OneUseTransform,
  registry: ReadonlyMap<string, number>,
): HTMLElement {
  const wrap = el('div');

  if (transform.reusedNames.length === 0) {
    wrap.appendChild(
      el('p', {
        class: 'verdict-detail',
        text:
          'No attribute appears in two rows, so the transform is a no-op here beyond appending :1 to every label. Put the same attribute in two branches and watch it act.',
      }),
    );
  } else {
    wrap.appendChild(
      el(
        'p',
        { class: 'verdict-detail' },
        el('strong', {
          text: `${transform.reusedNames.join(', ')} appears in more than one row. `,
        }),
        'FAME requires the row-labelling map to be injective, so each occurrence becomes a separate attribute in the universe.',
      ),
    );
  }

  const table = el('table');
  table.appendChild(
    el(
      'caption',
      { text: 'Attribute as written, the row labels it becomes, and the key cost' },
    ),
  );
  table.appendChild(
    el(
      'thead',
      {},
      el(
        'tr',
        {},
        el('th', { text: 'Attribute' }),
        el('th', { text: 'Row labels in this policy' }),
        el('th', { class: 'num', text: 'Copies a key must carry (k)' }),
        el('th', { class: 'num', text: 'G1 elements per holder' }),
      ),
    ),
  );
  const body = el('tbody');
  for (const rec of transform.records) {
    const k = registry.get(rec.name) ?? rec.copiesUsedHere;
    body.appendChild(
      el(
        'tr',
        {},
        el('td', { text: rec.name }),
        el('td', {}, el('code', { text: rec.labels.join(' , ') })),
        el('td', { class: 'num', text: String(k) }),
        el('td', { class: 'num', text: String(3 * k) }),
      ),
    );
  }
  table.appendChild(body);
  wrap.appendChild(scroller('One-use transform table', table));
  return wrap;
}

/* -------------------------------------------------------------------------- */
/* MSP matrix                                                                 */
/* -------------------------------------------------------------------------- */

export function renderMatrix(
  msp: Msp,
  coverage?: ReadonlyMap<number, boolean>,
  reconstruction?: Reconstruction,
): HTMLElement {
  const table = el('table');
  table.appendChild(
    el('caption', {
      text: `M is ${msp.rows.length} x ${msp.columns} over Z_p. Column 1 carries the secret; every other column was allocated by one gate.`,
    }),
  );

  const headRow = el('tr', {}, el('th', { text: 'Row' }), el('th', { text: 'pi(i)' }));
  for (let c = 1; c <= msp.columns; c++) {
    headRow.appendChild(
      el('th', {
        class: 'num',
        text: c === 1 ? 'col 1 (secret)' : `col ${c}`,
      }),
    );
  }
  if (reconstruction?.satisfied) headRow.appendChild(el('th', { class: 'num', text: 'gamma_i' }));
  table.appendChild(el('thead', {}, headRow));

  const body = el('tbody');
  for (const row of msp.rows) {
    const held = coverage?.get(row.index);
    const tr = el('tr', {
      class: held === undefined ? '' : held ? 'row-held' : 'row-missing',
    });
    tr.appendChild(el('td', { class: 'num', text: String(row.index) }));
    tr.appendChild(
      el(
        'td',
        {},
        el('code', { text: row.label }),
        held === undefined ? null : held ? statusChip('pass', 'held') : statusChip('fail', 'missing'),
      ),
    );
    for (const v of row.vector) {
      tr.appendChild(el('td', { class: 'num', text: fieldEntry(v, ORDER) }));
    }
    if (reconstruction?.satisfied) {
      const g = reconstruction.coefficients.get(row.index);
      tr.appendChild(
        el('td', {
          class: 'num',
          text: g === undefined || g === 0n ? '0' : fieldEntry(g, ORDER),
        }),
      );
    }
    body.appendChild(tr);
  }
  table.appendChild(body);
  return scroller('Monotone span program matrix', table);
}

/**
 * The reconstruction, computed on screen: the Lagrange steps, then the actual
 * linear combination of the rows.
 *
 * This recomputes sum(gamma_i * M_i) from the matrix rather than asserting that
 * decryption worked. Two different things can be checked; only one of them is
 * evidence.
 */
export function renderReconstruction(msp: Msp, rec: Reconstruction): HTMLElement {
  const wrap = el('div');

  if (!rec.satisfied) {
    wrap.appendChild(
      el('p', {
        class: 'verdict-detail',
        text: 'No satisfying set of rows, so there are no coefficients to reconstruct with.',
      }),
    );
    return wrap;
  }

  const steps = el('ul', { class: 'honesty-list' });
  for (const step of rec.lagrangeSteps) {
    if (step.points.length === 1) {
      steps.appendChild(
        el('li', {
          text: `Gate ${step.gateLabel}: one satisfied input at position ${step.points[0]}, so the Lagrange basis is just 1.`,
        }),
      );
      continue;
    }
    const terms = step.points
      .map((p, i) => `lambda_${p} = ${fieldEntry(step.basis[i], ORDER)}`)
      .join(',  ');
    steps.appendChild(
      el('li', {
        text: `Gate ${step.gateLabel}: interpolate at x = 0 through positions ${step.points.join(', ')} -> ${terms}`,
      }),
    );
  }
  wrap.appendChild(el('h4', { text: 'Lagrange, gate by gate' }));
  wrap.appendChild(steps);

  const combined = combineRows(msp, rec.coefficients);
  const ok = isTargetVector(combined);
  wrap.appendChild(el('h4', { text: 'The combination, recomputed from the matrix' }));
  wrap.appendChild(
    formula(
      'The reconstruction, recomputed from the matrix rows',
      `sum gamma_i * M_i  =  (${combined.map((x) => fieldEntry(x, ORDER)).join(', ')})`,
    ),
  );
  wrap.appendChild(
    el(
      'p',
      { class: 'verdict-detail' },
      ok
        ? statusChip('pass', 'equals (1, 0, ..., 0)')
        : statusChip('fail', 'does not equal (1, 0, ..., 0)'),
      ' This is equation 2.1 from the paper, evaluated here on the rows above rather than inferred from the fact that decryption succeeded.',
    ),
  );
  return wrap;
}

/* -------------------------------------------------------------------------- */
/* The KEM boundary                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Where attribute-based encryption stops and ordinary AEAD starts.
 *
 * FAME's message space is one GT element. The record is not, and must not be,
 * ABE-encrypted; the paper recommends exactly this KEM/KDF/AEAD shape. Drawing
 * the boundary is the difference between teaching the truth and implying that
 * the policy is somehow wrapped around the bytes of the record.
 */
export function renderPipeline(
  env: Envelope | null,
  aesKeyHex: string | null,
  encapsulatedHex: string | null,
): HTMLElement {
  const stage = (
    kicker: string,
    title: string,
    body: string,
    value: Child,
    cls = '',
  ): HTMLElement =>
    el(
      'div',
      { class: `pipe-stage ${cls}` },
      el('span', { class: 'pipe-kicker', text: kicker }),
      el('strong', { text: title }),
      el('p', { class: 'pipe-body', text: body }),
      value,
    );

  const arrow = (): HTMLElement =>
    el('span', { class: 'pipe-arrow', text: '->', attrs: { 'aria-hidden': 'true' } });

  return el(
    'div',
    { class: 'pipe' },
    stage(
      'attribute-based',
      'FAME encapsulates',
      'A fresh random element of GT is encrypted under the policy. This is the only attribute-based step.',
      env && encapsulatedHex
        ? el('span', { class: 'pipe-value' }, elementRef('GT', encapsulatedHex))
        : el('span', { class: 'pipe-value', text: 'not sealed yet' }),
      'pipe-stage-abe',
    ),
    arrow(),
    stage(
      'key derivation',
      'HKDF-SHA-256',
      `576 bytes of Fp12 in, 32 bytes out. info = "${HKDF_INFO}".`,
      el('span', {
        class: 'pipe-value',
        text: aesKeyHex ? `AES key ${aesKeyHex.slice(0, 16)}…` : 'not derived yet',
      }),
    ),
    arrow(),
    stage(
      'symmetric',
      'AES-256-GCM',
      `The record itself. ${GCM_NONCE_BYTES}-byte nonce, ${GCM_TAG_BYTES}-byte tag, and the policy string as associated data.`,
      el('span', {
        class: 'pipe-value',
        text: env
          ? `${env.sealed.ciphertext.length} bytes, nonce ${toHex(env.sealed.nonce).slice(0, 12)}…`
          : 'not sealed yet',
      }),
    ),
  );
}

/* -------------------------------------------------------------------------- */
/* Verdicts                                                                   */
/* -------------------------------------------------------------------------- */

export function renderVerdict(attempt: Attempt): HTMLElement {
  const tone = attempt.outcome === 'opened' ? 'pass' : attempt.outcome === 'blocked' ? 'warn' : 'fail';
  const cls = attempt.outcome === 'opened' ? 'verdict-pass' : attempt.outcome === 'blocked' ? 'verdict-warn' : 'verdict-fail';

  const box = el(
    'div',
    { class: `verdict ${cls}`, attrs: { 'data-outcome': attempt.outcome, 'data-code': attempt.code } },
    el(
      'div',
      { class: 'verdict-head' },
      el('span', { class: 'verdict-who', text: attempt.who }),
      statusChip(tone, attempt.headline),
      el('span', { class: 'code-tag', text: attempt.code }),
    ),
    el('p', { class: 'verdict-detail', text: attempt.detail }),
  );

  const facts = el('ul', { class: 'honesty-list' });
  facts.appendChild(
    el('li', {
      text: `Policy satisfied: ${attempt.reconstruction.satisfied ? 'yes' : 'no'}`,
    }),
  );
  facts.appendChild(
    el('li', {
      text: `Decrypt returned a GT element: ${attempt.recovered ? 'yes' : 'no, it never ran'}`,
    }),
  );
  facts.appendChild(
    el('li', {
      text: `It equalled the encapsulated element: ${attempt.recoveredMatches ? 'yes' : 'no'}`,
    }),
  );
  facts.appendChild(
    el('li', { text: `AES-GCM verified the tag: ${attempt.aeadAccepted ? 'yes' : 'no'}` }),
  );
  facts.appendChild(
    el('li', {
      class: 'fact-pairings',
      text:
        attempt.pairings === 0
          ? 'Pairings computed: 0 — the policy check failed before any were needed'
          : `Pairings computed: ${attempt.pairings} — and it is six for every policy, however large`,
    }),
  );
  box.appendChild(facts);

  if (attempt.plaintext !== null) {
    box.appendChild(el('div', { class: 'verdict-plain', text: attempt.plaintext }));
  }
  return box;
}

/* -------------------------------------------------------------------------- */
/* The collusion ledger -- the headline mechanism                             */
/* -------------------------------------------------------------------------- */

/**
 * Why a pooled key fails, term by term.
 *
 * Decryption's numerator pairs the ciphertext rows against sk0 = h^(Br) from
 * ONE key. Its denominator pairs each row's key component -- carrying whichever
 * key it came from -- against ct0. For a row whose component came from the same
 * key as sk0, the Br cancels. For a borrowed row it does not, and what survives
 * is exactly
 *
 *     e(H(pi(i), l, t), h) ^ (gamma_i * s_t * (Br_base - Br_owner))
 *
 * The table below prints Br_base - Br_owner for every row and every l. Zeros
 * cancel. Anything else is the reason the record stays shut.
 */
export function renderLedger(analysis: CollusionAnalysis): HTMLElement {
  const table = el('table', { class: 'ledger' });
  table.appendChild(
    el('caption', {
      text: 'Per row: whose key the component came from, and the blinding difference Br_base - Br_owner for l = 1, 2, 3.',
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
        el('th', { text: 'pi(i)' }),
        el('th', { text: 'Component from' }),
        el('th', { class: 'num', text: 'l = 1' }),
        el('th', { class: 'num', text: 'l = 2' }),
        el('th', { class: 'num', text: 'l = 3' }),
        el('th', { text: 'Outcome' }),
      ),
    ),
  );
  const body = el('tbody');
  for (const row of analysis.rows) {
    const tr = el('tr', { class: row.coherent ? 'row-held' : 'row-missing' });
    tr.appendChild(el('td', { class: 'num', text: String(row.rowIndex) }));
    tr.appendChild(el('td', {}, el('code', { text: row.label })));
    tr.appendChild(el('td', { text: row.holder }));
    for (const d of row.brDelta) {
      tr.appendChild(
        el('td', {
          class: `num ${d === 0n ? 'cancels' : 'survives'}`,
          text: d === 0n ? '0' : fieldEntry(d, ORDER),
        }),
      );
    }
    tr.appendChild(
      el(
        'td',
        {},
        row.coherent
          ? statusChip('pass', 'cancels')
          : statusChip('fail', 'survives'),
      ),
    );
    body.appendChild(tr);
  }
  table.appendChild(body);
  return scroller('Blinding-cancellation ledger', table);
}

/** Observed residual vs the residual predicted from the r values. */
export function renderResidual(analysis: CollusionAnalysis, gtHex: (x: unknown) => string): HTMLElement {
  const observed = analysis.residualObserved ? gtHex(analysis.residualObserved) : null;
  const predicted = gtHex(analysis.residualPredicted);
  const wrap = el('div');
  wrap.appendChild(
    el(
      'p',
      { class: 'verdict-detail' },
      'Two routes to the same number. One divides what decryption produced by what was encapsulated. The other multiplies out the surviving terms above, from the r and s values, without calling decrypt at all.',
    ),
  );
  const table = el('table');
  table.appendChild(
    el(
      'tbody',
      {},
      el(
        'tr',
        {},
        el('th', { text: 'recovered / encapsulated' }),
        el('td', {}, el('code', { text: observed ? `${observed.slice(0, 24)}…${observed.slice(-16)}` : 'decryption never ran' })),
      ),
      el(
        'tr',
        {},
        el('th', { text: 'predicted leftover blinding' }),
        el('td', {}, el('code', { text: `${predicted.slice(0, 24)}…${predicted.slice(-16)}` })),
      ),
      el(
        'tr',
        {},
        el('th', { text: 'byte-for-byte equal' }),
        el(
          'td',
          {},
          analysis.routesAgree
            ? statusChip('pass', 'yes', 'all 576 bytes')
            : statusChip('fail', 'no'),
        ),
      ),
      el(
        'tr',
        {},
        el('th', { text: 'residual is the identity' }),
        el(
          'td',
          {},
          analysis.residualIsOne
            ? statusChip('pass', 'yes', 'decryption is correct')
            : statusChip('fail', 'no', 'the record stays shut'),
        ),
      ),
    ),
  );
  wrap.appendChild(scroller('Residual comparison', table));
  return wrap;
}

/* -------------------------------------------------------------------------- */
/* People                                                                     */
/* -------------------------------------------------------------------------- */

export interface PersonView {
  readonly name: string;
  readonly attributes: readonly string[];
  readonly revoked: boolean;
  readonly key: KeyRecord | undefined;
  readonly stale: readonly string[];
}

export function renderPeople(
  people: readonly PersonView[],
  onOpen: (name: string) => void,
  onRevoke: (name: string) => void,
  onReissue: (name: string) => void,
  canOpen: boolean,
): HTMLElement {
  const list = el('ul', { class: 'people' });
  for (const p of people) {
    const card = el('li', { class: `person${p.revoked ? ' person-revoked' : ''}` });
    card.appendChild(
      el(
        'div',
        { class: 'stack-row' },
        el('span', { class: 'person-name', text: p.name }),
        p.revoked ? statusChip('warn', 'revoked') : null,
        p.stale.length > 0 ? statusChip('warn', 'key stale', p.stale.join(', ')) : null,
      ),
    );
    card.appendChild(
      el('div', { class: 'person-attrs', text: p.key ? p.key.issued.key.labels.join(' , ') : p.attributes.join(' , ') }),
    );
    card.appendChild(
      el('div', {
        class: 'person-meta',
        text: p.key
          ? `key #${p.key.serial} · ${p.key.elements} group elements · ${p.key.issued.key.sk.size} attribute components`
          : 'no key issued',
      }),
    );
    const row = el('div', { class: 'stack-row' });
    const openBtn = button(`Try to open`, () => onOpen(p.name), 'btn btn-small btn-primary');
    openBtn.setAttribute('aria-label', `Try to open the sealed record with ${p.name}'s key`);
    openBtn.disabled = !canOpen || !p.key;
    row.appendChild(openBtn);

    const reissue = button('Re-issue key', () => onReissue(p.name), 'btn btn-small');
    reissue.setAttribute('aria-label', `Issue ${p.name} a fresh key at the current k`);
    row.appendChild(reissue);

    const revoke = button(p.revoked ? 'Reinstate' : 'Revoke', () => onRevoke(p.name), 'btn btn-small btn-danger');
    revoke.setAttribute(
      'aria-label',
      p.revoked ? `Reinstate ${p.name}` : `Revoke ${p.name} from the authority's list`,
    );
    row.appendChild(revoke);

    card.appendChild(row);
    list.appendChild(card);
  }
  return list;
}

/* -------------------------------------------------------------------------- */
/* Stage sequencing                                                           */
/* -------------------------------------------------------------------------- */

export interface Stage {
  readonly title: string;
  readonly body: string;
  readonly tone?: 'surprise' | 'final' | 'good';
  readonly extra?: Child;
}

/**
 * Reveal a sequence of stages into `host`, one per tick.
 *
 * The motion is the teaching: pooling, then the policy PASSING, then decryption
 * running, then the comparison, in that order, is the whole argument. Under
 * prefers-reduced-motion every stage lands at once -- the content is identical
 * either way, because nothing here is revealed by an animation.
 */
export function playStages(host: HTMLElement, stages: readonly Stage[], done?: () => void): void {
  clear(host);
  const reduce =
    typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

  const build = (s: Stage, index: number): HTMLElement => {
    const cls = s.tone ? ` stage-${s.tone}` : '';
    const node = el(
      'div',
      { class: `stage${cls}${reduce ? '' : ' stage-enter'}`, attrs: { 'data-stage': String(index + 1) } },
      el('h4', { text: `${index + 1}. ${s.title}` }),
      el('p', { text: s.body }),
    );
    if (s.extra) append(node, [s.extra]);
    return node;
  };

  if (reduce) {
    stages.forEach((s, i) => host.appendChild(build(s, i)));
    done?.();
    return;
  }

  let i = 0;
  const tick = (): void => {
    if (i >= stages.length) {
      done?.();
      return;
    }
    host.appendChild(build(stages[i], i));
    i += 1;
    setTimeout(tick, 180);
  };
  tick();
}
