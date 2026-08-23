import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * A HEADROOM probe, deliberately narrower than the 320 CSS px WCAG 1.4.10 asks
 * for. Scanning AT 320 does not work: a sibling lab in this batch shipped a
 * defect whose min-content floor was 318px, so it fit at 320 and failed at 380
 * only once Linux font metrics in CI inflated it — a single-width check cannot
 * see a floor sitting just under that width. 280 asserts the floor is low
 * enough that no font-metric delta can push it back over 320.
 */
export const REFLOW = { width: 280, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each corrects a way the old
 * fleet-template gate reported coverage it did not have:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`, which BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising
 *     it. That matters here specifically: the collusion exhibit reveals its
 *     six stages one per tick with a `stage-in` keyframe, and the reduced-
 *     motion block is what turns that into a single instantaneous render.
 *     This gate sets the preference through `emulateMedia`, asserts from
 *     inside the page that it took effect (`test.use({ reducedMotion })` is a
 *     measured no-op on Playwright 1.62), and injects nothing.
 *
 *  2. NOTHING IS REVEALED FROM SCRIPT. The old drive stripped every `[hidden]`
 *     and set every `<details>.open` by JS before its only scan. This page has
 *     seven `<details class="disclose">` blocks -- the KEM boundary, the
 *     BSW07-versus-FAME argument, the paper's one-use wording, the matrix
 *     construction, what a key is, the residual derivation, and what real
 *     revocation would cost -- and every one of them SHIPS SHUT. The state a
 *     reader arrives at is scanned first, and each disclosure is then opened
 *     by clicking its `<summary>`, which is the route a reader has.
 *
 *  3. THE DRIVE NAMES WHAT IT TOUCHES AND WAITS ON REAL SIGNALS. No fixed
 *     timeouts, no `.catch(() => {})`. Every step waits on a DOM completion
 *     signal the page actually produces: a `[data-code]` verdict, a
 *     `[data-stage="6"]` collusion stage, a `[data-sealed]` envelope serial.
 *     This lab computes real BLS12-381 pairings on click, so a step that waits
 *     on a timer instead of a signal is a race by construction.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Every surface that
 *     carries this lab's meaning is a `color-mix()` fill axe files under
 *     `incomplete` rather than judging: all four `.chip-*` tones, the three
 *     `.verdict-*` borders, the held/missing row tints in the matrix and the
 *     collusion ledger, the hero aside's accent wash, the `.honesty` panel and
 *     the shared bar's ink.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE.
 *     `nontext.ts` measures every control's boundary as painted, and
 *     `expectNoHorizontalOverflow` adds the 1.4.10 check axe has no rule for --
 *     which is the live risk on a page whose matrix, ledger and one-use tables
 *     are wide by nature.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it. Transitions
 * also drain in waves rather than one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves -- hence six consecutive
 * quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish are excluded rather than waited on, a
 * wall-clock budget inside the page gives up and proceeds, and Playwright's
 * own timeout is the backstop.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode is an element whose only route to its visible state is an
 * animation, in a stylesheet whose reduced-motion block cancels that animation
 * without restoring the end state -- the element then renders at `opacity: 0`
 * for every reader with the preference set. This lab deliberately avoids that
 * shape: `stage-in` animates `transform` only and every stage is appended
 * already visible, and under reduced motion `playStages` appends all six at
 * once. This assertion is what keeps that a measurement rather than a reading
 * of the source.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from page creation.
 *
 * Every exhibit here renders synchronously into a host div, so a renderer that
 * throws leaves that host EMPTY -- and an empty region is exactly what a scan
 * reports as perfectly accessible. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's hero
 * IS a `<header class="cl-hero">`, and it is a direct child of `#app` rather
 * than of any sectioning element -- so it would imply a second banner if the
 * bar's `dedupeBanner()` did not demote it. That makes this assertion load
 * bearing here rather than defensive: it is measuring a demotion that actually
 * has to happen on this page.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false;
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab styles two lists `list-style: none` -- `.tree` (the access tree)
 * and `.people` (the key cards) -- which is the declaration that makes Safari
 * and VoiceOver drop a list's implicit role. Neither compensates with an
 * explicit `role="list"` today, so the assertion checks the SHAPE of any role
 * that does appear: an explicit role on a `ul`/`ol` must be `list` (anything
 * else orphans every `<li>` under it), and a `role="list"` must never sit on
 * an empty element, because axe applies `aria-required-children` to the
 * explicit role and fails it the day the list renders with no items.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`,
      ),
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children',
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect and assert the content
 * every scan relies on is really there -- including the lab's DEFAULTS.
 *
 * A navigation that resolves proves nothing. This page runs a full BLS12-381
 * Setup, five KeyGens and an Encrypt before it can paint anything, all of it
 * asynchronous; a renderer that threw would leave `#exhibits` empty, and an
 * empty region scans clean. So the arrival state is asserted item by item.
 */
export async function boot(page: Page): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful.
  page.setDefaultTimeout(30_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);

  // Dark is the only theme, pinned before first paint and also on the tag.
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');

  // Everything below waits on the app having finished its first seal.
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true');

  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The chrome ──────────────────────────────────────────────────────────
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveText('Attribute Gate');
  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);
  await expect(page.locator('.scripture-footer')).toHaveCount(1);

  // No theme control of any kind: the fleet's toggle was removed and this lab
  // never had one. The shared CSS would merely hide a lab-local toggle, which
  // leaves a dead-but-present element; asserting zero catches the day one is
  // added without going through that list.
  await expect(
    page.locator(
      '#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]',
    ),
  ).toHaveCount(0);

  // ── The arrival state ───────────────────────────────────────────────────
  await expect(page.locator('section.panel')).toHaveCount(8);
  await expect(page.locator('#preset')).toHaveValue('headline');
  await expect(page.locator('[data-host="formula"] code')).toHaveText(
    '((Doctor AND Cardiology) OR Emergency)',
  );
  // Sealed on load, so the whole page is live before anyone clicks anything.
  await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
  await expect(page.locator('[data-host="seal-status"]')).toHaveAttribute('role', 'status');

  // Three MSP rows for the headline policy, and the matrix really rendered.
  await expect(page.locator('[data-host="matrix"] tbody tr')).toHaveCount(3);
  await expect(page.locator('[data-host="transform"] tbody tr')).toHaveCount(3);

  // Five key cards, each with a key issued.
  await expect(page.locator('.person')).toHaveCount(5);
  await expect(page.locator('.person-attrs').first()).toContainText('Doctor:1');

  // Nothing has been attempted yet, so the result regions are empty.
  await expect(page.locator('[data-host="attempt"]')).toBeEmpty();
  await expect(page.locator('[data-host="collusion"]')).toBeEmpty();
  await expect(page.locator('[data-host="escrow"]')).toBeEmpty();
  await expect(page.locator('[data-host="revocation"]')).toBeEmpty();

  // ── Every disclosure ships shut ─────────────────────────────────────────
  await expect(page.locator('details.disclose')).toHaveCount(7);
  await expect(page.locator('details.disclose[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, 'first paint');
}

/**
 * Assert the page does not require horizontal scrolling (WCAG 1.4.10, AA).
 *
 * axe has no rule for this. The live risk on this page is a wide table: the
 * MSP matrix grows a column per AND gate, the collusion ledger is seven
 * columns, and the one-use table carries a hex-free but long label column.
 * All three live inside `.scroller` (`overflow-x: auto`), so what this checks
 * is that the scroller is doing its job rather than pushing the document
 * sideways -- and at 380px that is precisely the failure it would show.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width -- naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 *
 * This lab leans on scrollers by design -- the matrix, the ledger, the
 * transform table, the residual comparison and the failure-code reference are
 * all `.scroller` regions -- so unlike most of the fleet this assertion is
 * load bearing at every state. `dom.ts`'s `scroller()` gives each one
 * `role="region"`, an `aria-label` and `tabindex="0"`; this measures the
 * outcome rather than trusting the helper.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen.
 * `display: none` and `visibility: hidden` DO remove an element from the tab
 * order, so those are skipped rather than flagged.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` at full
 * opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`,
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops. The collection pass turns "one run per defect" into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding and then fails at the end, so a green
 * collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has any other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node. This page has two generated marks that matter -- the
 * `.select-wrap::after` chevron on every styled `<select>`, which is the ONLY
 * affordance saying a select is a select once `appearance: none` removes the
 * native one, and the `.disclose-summary::before` triangle on all seven
 * disclosures.
 *
 * IT IS CALLED FROM `scan()`, deliberately. Fleet-wide this oracle had been
 * called from inside a soft wrapper AFTER its `if (!COLLECTING) return` guard,
 * so in a strict run -- which is every run in CI -- it never executed at all.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`,
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive. It has
 * either been fixed -- delete the entry, which is the point -- or the drive
 * stopped reaching the state that shows it, which is a coverage regression.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state -- see `expectNotBlank`.
 *  - `violations` -- the usual WCAG A/AA failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` -- axe's "could not decide" bucket, which never reaches the
 *    violations array. Only `color-contrast` is allowed to remain there, and
 *    only because the next assertion computes those ratios arithmetically.
 *    Everything else in that bucket is a real result axe could not finish,
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides. This page leans on getting that right: the
 *    scroller regions all pair an `aria-label` with `role="region"`, and the
 *    live result hosts pair theirs with `role="status"`.
 *  - arithmetic contrast -- composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted.
 *  - non-text contrast and generated content -- SC 1.4.11, ratcheted.
 *  - keyboard reachability of scrolling regions -- WCAG 2.1.1.
 *  - no focusable element that paints nothing -- WCAG 2.4.3 / 2.4.7.
 *  - reflow -- WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);

  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first.
  // Chained as `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs
  // those four best-practice rules and NOT ONE WCAG RULE, while a green result
  // reads exactly like a full A/AA pass.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, and this page has the shape they catch: a sticky
  // `<header role="banner">` above a `<div id="app">` holding a
  // `<header class="cl-hero">` with an `<aside>` inside it, plus a `<nav>` in
  // the shared bar and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk with the exemption lifted. axe skips this content and
  // so does the default walk, so this second call is the only thing that ever
  // measures it. On this page every aria-hidden element is an inline SVG icon
  // or the panel-number span, which is checked rather than assumed.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true),
      ),
    ),
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/* -------------------------------------------------------------------------- */
/* The drive                                                                  */
/* -------------------------------------------------------------------------- */

/** Wait for the app to have finished resealing after a policy change. */
async function waitSealed(page: Page): Promise<void> {
  await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Shaping this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, as a reader gets it: headline policy,
 *    record already sealed, nothing attempted, all seven disclosures shut.
 *
 *  - EVERY VERDICT TONE IS REACHED. The page has three -- opened (pass),
 *    denied (fail) and blocked (warn) -- plus MALFORMED_POLICY, and each one
 *    paints a different `color-mix()` border that axe files as incomplete. A
 *    drive that only ever succeeds scans one third of the surfaces the lab
 *    exists to show.
 *
 *  - THE EXPENSIVE STATES ARE THE POINT. The collusion walkthrough is six
 *    stages including two verdicts and a seven-column ledger; the escrow and
 *    revocation fixtures each render multi-stage sequences. All three are real
 *    BLS12-381 work triggered by a click, so every wait is on the last stage's
 *    `data-stage` marker rather than a timer.
 *
 *  - HOVER PERSISTS AFTER A CLICK, so it is the state a reader occupies the
 *    instant after pressing a button, and `.btn:hover` repaints both fill and
 *    border. It is scanned explicitly.
 */
export async function driveAllStates(page: Page, prefix: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${prefix} / ${s}`);

  await scanAt('arrival: headline policy sealed, nothing attempted, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── A successful open: the pass verdict and the plaintext ───────────────
  await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
  await expect(page.locator('[data-host="attempt"] .verdict')).toHaveAttribute(
    'data-outcome',
    'opened',
  );
  await expect(page.locator('[data-host="attempt"] .verdict-plain')).toContainText('PATIENT');
  await scanAt('Alice opens the record — pass verdict, plaintext, matrix rows all held');

  // ── A refusal: the fail verdict, the named code, the highlighted rows ───
  await page.getByRole('button', { name: /Try to open the sealed record with Bob/ }).click();
  await expect(page.locator('[data-host="attempt"] .verdict')).toHaveAttribute(
    'data-code',
    'POLICY_UNSATISFIED',
  );
  await expect(page.locator('[data-host="matrix"] tr.row-missing')).toHaveCount(2);
  await expect(page.locator('.node-unsat').first()).toBeVisible();
  await scanAt('Bob is refused — fail verdict, unsatisfied tree nodes and missing matrix rows');

  // ── Every disclosure, opened through its summary ────────────────────────
  const summaries = page.locator('details.disclose > summary');
  const count = await summaries.count();
  expect(count, 'seven disclosures ship on this page').toBe(7);
  for (let i = 0; i < count; i++) {
    await summaries.nth(i).click();
    await expect(page.locator('details.disclose[open]')).toHaveCount(i + 1);
  }
  await scanAt('all seven disclosures open — formulas, the paper quotes, the derivation');
  for (let i = 0; i < count; i++) await summaries.nth(i).click();
  await expect(page.locator('details.disclose[open]')).toHaveCount(0);

  // ── MALFORMED_POLICY, the only fail-closed path a reader can trigger ────
  await page.fill('#custom-attr', 'Doctor:1');
  await page.getByRole('button', { name: 'Add a custom attribute' }).click();
  await expect(page.locator('[data-host="seal-status"] .verdict-fail')).toHaveAttribute(
    'data-code',
    'MALFORMED_POLICY',
  );
  await scanAt('MALFORMED_POLICY — a reserved colon in an attribute name, refused by name');

  // A valid custom attribute recovers, and the unsealed warning appears.
  await page.fill('#custom-attr', 'Radiology');
  await page.getByRole('button', { name: 'Add a custom attribute' }).click();
  await expect(page.locator('[data-host="seal-status"] .verdict-warn')).toBeVisible();
  await scanAt('policy edited but not resealed — the warn verdict');

  await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
  await waitSealed(page);

  // ── The reuse preset: the one-use transform actually acting ─────────────
  await page.selectOption('#preset', 'reuse');
  await expect(page.locator('[data-host="formula"] code')).toHaveText(
    '((Doctor AND Cardiology) OR (Doctor AND Emergency))',
  );
  await expect(page.locator('[data-host="matrix"] tbody tr')).toHaveCount(4);
  await expect(page.locator('.person .chip-warn')).not.toHaveCount(0);
  await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
  await waitSealed(page);
  await scanAt('reuse preset — Doctor indexed to two rows, stale-key chips on the holders');

  await page.getByRole('button', { name: 'Re-issue every key' }).click();
  await expect(page.locator('.person .chip-warn')).toHaveCount(0);
  await scanAt('keys re-issued at the new k — the stale chips clear');

  // ── The threshold preset: the Lagrange step ─────────────────────────────
  await page.selectOption('#preset', 'threshold');
  await expect(page.locator('[data-host="formula"] code')).toHaveText(
    '2-of-3(Doctor, Cardiology, OnCall)',
  );
  await page.selectOption('#recon-who', 'Alice');
  await expect(page.locator('[data-host="reconstruction"]')).toContainText('lambda_1');
  await expect(page.locator('[data-host="reconstruction"] .chip-pass')).not.toHaveCount(0);
  await scanAt('threshold preset — Lagrange basis and the recomputed combination');

  await page.selectOption('#recon-who', 'Dan');
  await expect(page.locator('[data-host="reconstruction"] .chip-fail')).not.toHaveCount(0);
  await scanAt('threshold preset — a holder who does not satisfy it');

  // ── Editing a gate directly ─────────────────────────────────────────────
  const gateSelect = page.locator('select[id^="gate-"]').first();
  await gateSelect.selectOption('3');
  await expect(page.locator('[data-host="formula"] code')).toContainText('AND');
  await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
  await waitSealed(page);
  await scanAt('gate switched from 2-of-3 to AND through its own select');

  await gateSelect.selectOption('2');
  await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
  await waitSealed(page);

  // ── Collusion: the six-stage walkthrough ────────────────────────────────
  await page.selectOption('#preset', 'headline');
  await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
  await waitSealed(page);
  await page.selectOption('#collude-a', 'Bob');
  await page.selectOption('#collude-b', 'Eve');
  await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
  await expect(page.locator('[data-host="collusion"] [data-stage="6"]')).toBeVisible();
  await expect(page.locator('[data-host="collusion"] .ledger td.survives').first()).toBeVisible();
  await expect(
    page.locator('[data-host="collusion"] .verdict[data-code="COLLUSION_BLOCKED"]'),
  ).toHaveCount(2);
  await scanAt('collusion — six stages, the ledger, both splice directions blocked');

  // The two non-collusion branches, which render a different panel entirely:
  // one holder already qualifies alone, or the union still does not qualify.
  await page.selectOption('#collude-a', 'Alice');
  await page.selectOption('#collude-b', 'Carol');
  await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
  await expect(
    page.locator('[data-host="collusion"] [data-scenario="not-collusion"]'),
  ).toBeVisible();
  await scanAt('collusion — a holder who already qualifies alone, so it is not collusion');

  await page.selectOption('#collude-a', 'Bob');
  await page.selectOption('#collude-b', 'Dan');
  await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
  await expect(
    page.locator('[data-host="collusion"] [data-scenario="not-collusion"]'),
  ).toContainText('not collusion resistance');
  await scanAt('collusion — a pair whose union still fails the policy check');

  // Same-holder rejection: the one branch that renders no stages at all.
  await page.selectOption('#collude-a', 'Alice');
  await page.selectOption('#collude-b', 'Alice');
  await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
  await expect(page.locator('[data-host="collusion"]')).toContainText('two different holders');
  await scanAt('collusion — the same holder chosen twice, refused with a reason');

  // ── Escrow ──────────────────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Mint an authority key, then decrypt' }).click();
  await expect(page.locator('[data-host="escrow"] [data-stage="2"]')).toBeVisible();
  await expect(page.locator('[data-host="escrow"] .verdict[data-outcome="opened"]')).toBeVisible();
  await scanAt('escrow — msk mints a satisfying key, then that key decrypts');

  // ── Revocation ──────────────────────────────────────────────────────────
  await page.selectOption('#revoke-who', 'Carol');
  await page.getByRole('button', { name: /Revoke, seal a new record/ }).click();
  await expect(page.locator('[data-host="revocation"] [data-stage="3"]')).toHaveAttribute(
    'data-opened',
    'true',
  );
  await expect(page.locator('.person-revoked')).not.toHaveCount(0);
  await scanAt('revocation — a revoked key opens a record sealed after the revocation');

  // The other branch: a holder the live policy does not admit at all.
  await page.selectOption('#revoke-who', 'Dan');
  await page.getByRole('button', { name: /Revoke, seal a new record/ }).click();
  await expect(page.locator('[data-host="revocation"] [data-stage="3"]')).toHaveAttribute(
    'data-opened',
    'true',
  );
  await scanAt('revocation — the fixture falls back to a policy the holder satisfies');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.getByRole('button', { name: 'Seal the record under this policy' }).hover();
  await scanAt('a primary button hovered — accent fill and accent border');

  await page.getByRole('button', { name: 'Re-issue every key' }).hover();
  await scanAt('a secondary button hovered — surface-3 fill, accent border');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#record-input').focus();
  await expect(page.locator('#record-input')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.locator('#preset').focus();
  await scanAt('a styled select focused');

  await page.locator('.scroller').first().focus();
  await scanAt('a scrollable region focused — the keyboard route into the matrix');
}
