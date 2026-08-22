/**
 * Small DOM helpers.
 *
 * Two rules the accessibility gate enforces and this file makes easy to keep:
 *  - state is never carried by colour alone; `statusChip` always emits an icon,
 *    a word, and the colour together;
 *  - anything that scrolls is a labelled, focusable region.
 */

export type Child = Node | string | null | undefined | false;

export interface ElOptions {
  readonly class?: string;
  readonly text?: string;
  readonly html?: never;
  readonly attrs?: Record<string, string | number | boolean | undefined>;
  readonly on?: Partial<Record<keyof HTMLElementEventMap, (e: Event) => void>>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: ElOptions = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.class) node.className = options.class;
  if (options.text !== undefined) node.textContent = options.text;
  for (const [k, v] of Object.entries(options.attrs ?? {})) {
    if (v === undefined || v === false) continue;
    node.setAttribute(k, String(v));
  }
  for (const [k, fn] of Object.entries(options.on ?? {})) {
    node.addEventListener(k, fn as EventListener);
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/* -------------------------------------------------------------------------- */
/* Icons -- always paired with text, never the only signal                    */
/* -------------------------------------------------------------------------- */

export type IconName = 'pass' | 'fail' | 'warn' | 'info' | 'key' | 'lock';

const ICON_PATHS: Record<IconName, string> = {
  pass: 'M4 10.5l4 4 8-9',
  fail: 'M5 5l10 10M15 5L5 15',
  warn: 'M10 3l8 14H2zM10 8v4M10 14.5v.5',
  info: 'M10 2a8 8 0 100 16 8 8 0 000-16zM10 9v5M10 6v.5',
  key: 'M12.5 3a4.5 4.5 0 00-4.3 5.8L2 15v3h3l1-1v-2h2v-2h2l1.2-1.2A4.5 4.5 0 1012.5 3z',
  lock: 'M5 9V6a5 5 0 0110 0v3M3.5 9h13v9h-13z',
};

export function icon(name: IconName, cls = ''): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 20 20');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (cls) svg.setAttribute('class', cls);
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', ICON_PATHS[name]);
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', '2');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.appendChild(path);
  return svg;
}

export type Tone = 'pass' | 'fail' | 'warn' | 'neutral';

const TONE_ICON: Record<Tone, IconName> = {
  pass: 'pass',
  fail: 'fail',
  warn: 'warn',
  neutral: 'info',
};

/**
 * A state chip: icon + word + colour, in that order of importance.
 *
 * WCAG 1.4.1 -- the word carries the meaning on its own, so the chip still
 * reads correctly in greyscale and under any colour vision deficiency.
 */
export function statusChip(tone: Tone, label: string, extra = ''): HTMLElement {
  return el(
    'span',
    { class: `chip chip-${tone}`, attrs: { 'data-tone': tone } },
    icon(TONE_ICON[tone], 'chip-icon'),
    el('span', { class: 'chip-label', text: label }),
    extra ? el('span', { class: 'chip-extra', text: extra }) : null,
  );
}

/* -------------------------------------------------------------------------- */
/* Layout                                                                     */
/* -------------------------------------------------------------------------- */

export interface SectionOptions {
  readonly id: string;
  readonly number: string;
  readonly title: string;
  readonly lede: string;
}

export function section(opts: SectionOptions, ...children: Child[]): HTMLElement {
  return el(
    'section',
    { class: 'panel', attrs: { id: opts.id, 'aria-labelledby': `${opts.id}-h` } },
    el(
      'div',
      { class: 'panel-head' },
      el('span', { class: 'panel-num', text: opts.number, attrs: { 'aria-hidden': 'true' } }),
      el('h2', { class: 'panel-title', text: opts.title, attrs: { id: `${opts.id}-h` } }),
    ),
    el('p', { class: 'panel-lede', text: opts.lede }),
    ...children,
  );
}

/**
 * A progressive-disclosure block.
 *
 * This is where the depth lives. The page reads for a newcomer with every
 * disclosure shut; opening one gives the group elements, the exponents and the
 * paper's own wording. Nothing is behind a mode switch.
 */
export function disclosure(summary: string, ...children: Child[]): HTMLDetailsElement {
  const d = el('details', { class: 'disclose' });
  d.appendChild(el('summary', { class: 'disclose-summary' }, el('span', { text: summary })));
  const body = el('div', { class: 'disclose-body' });
  append(body, children);
  d.appendChild(body);
  return d;
}

/** A horizontally scrollable wrapper that keyboard users can reach and read. */
export function scroller(label: string, ...children: Child[]): HTMLElement {
  return el(
    'div',
    {
      class: 'scroller',
      attrs: { role: 'region', 'aria-label': label, tabindex: '0' },
    },
    ...children,
  );
}

/** A polite live region for results the user causes. */
export function liveRegion(label: string): HTMLElement {
  return el('div', {
    class: 'live',
    attrs: { role: 'status', 'aria-live': 'polite', 'aria-label': label },
  });
}

export function button(label: string, onClick: () => void, cls = 'btn'): HTMLButtonElement {
  return el('button', {
    class: cls,
    text: label,
    attrs: { type: 'button' },
    on: { click: onClick },
  });
}

/** A labelled native select with the appearance reset and a drawn chevron. */
export function select(
  labelText: string,
  options: { value: string; label: string }[],
  onChange: (value: string) => void,
  id: string,
  selected?: string,
): HTMLElement {
  const sel = el('select', {
    class: 'select',
    attrs: { id },
    on: {
      change: (e) => onChange((e.target as HTMLSelectElement).value),
    },
  });
  for (const o of options) {
    const opt = el('option', { text: o.label, attrs: { value: o.value } });
    if (selected !== undefined && o.value === selected) opt.selected = true;
    sel.appendChild(opt);
  }
  return el(
    'span',
    { class: 'field' },
    el('label', { class: 'field-label', text: labelText, attrs: { for: id } }),
    el('span', { class: 'select-wrap' }, sel),
  );
}

/* -------------------------------------------------------------------------- */
/* Formatting                                                                 */
/* -------------------------------------------------------------------------- */

/** Short hex fingerprint with an ellipsis, for group elements. */
export function shortHex(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** Monospace element display: the group tag, then the fingerprint. */
export function elementRef(group: string, hex: string): HTMLElement {
  return el(
    'span',
    { class: 'elref' },
    el('span', { class: 'elref-group', text: group }),
    el('code', { class: 'elref-hex', text: shortHex(hex) }),
  );
}

/** Render a field element small-negative-aware, so -1 does not read as p-1. */
export function fieldEntry(value: bigint, order: bigint): string {
  const window_ = 1_000_000n;
  if (value < window_) return value.toString();
  if (value > order - window_) return `-${(order - value).toString()}`;
  return `0x${value.toString(16).slice(0, 8)}…`;
}
