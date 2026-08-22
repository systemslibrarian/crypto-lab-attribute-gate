import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, with the
 * headline policy already sealed and nothing attempted; the shared skip link
 * focused; Alice opening the record and Bob being refused, so the pass and
 * fail verdict tones and the highlighted tree nodes and matrix rows are both
 * scanned; all seven disclosures opened through their own summaries and shut
 * again; MALFORMED_POLICY raised by typing a reserved colon into the custom
 * attribute field, and the unsealed warning that follows an accepted edit; the
 * reuse preset, where the one-use transform indexes Doctor into two rows and
 * every Doctor key goes stale, then clears on re-issue; the threshold preset's
 * Lagrange basis for a holder who satisfies it and one who does not; a gate
 * switched through its own select; the six-stage collusion walkthrough with
 * its ledger and both blocked splice directions, its coherent-key control
 * case, and its same-holder refusal; the escrow fixture's two steps; both
 * branches of the revocation fixture; three hover states and three focus
 * rings. Every one of those states is scanned, at desktop and phone width.
 *
 * Dark is the only theme this lab ships, so there is no second theme pass.
 *
 * See `gate.ts` for why nothing is injected into the page, why no disclosure
 * is opened from script, why the arrival state is asserted item by item rather
 * than assumed, and why `violations` is not the whole oracle.
 */
test('no WCAG A/AA violations at desktop width', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page);
  await driveAllStates(page, 'dark');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations at 380px', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page);
  await driveAllStates(page, 'dark @380px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
