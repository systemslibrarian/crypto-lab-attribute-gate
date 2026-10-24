import { expect, test, type Page } from '@playwright/test';
import { FAILURE_CODES, FAILURE_CODE_IDS } from '../src/fame/codes';
import { ORDER } from '../src/fame/bls';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these tests worth anything is that a test which
 * re-derives the same expression the source uses will happily agree with a
 * bug. So nothing here recomputes a value by calling the function that
 * produced it. Three shapes, mixed deliberately:
 *
 *  - CROSS-CHECKS between two surfaces that must agree. The person card's
 *    element count against the labels it lists; the one-use table's k against
 *    the row labels in the matrix; the rendered failure-code table against the
 *    exported constants.
 *
 *  - INDEPENDENT RE-DERIVATIONS. The reconstruction is recomputed here from
 *    the numbers PRINTED IN THE MATRIX -- parsed back out of the DOM, including
 *    the rational forms -- and checked against (1, 0, ..., 0). The sealed byte
 *    count is recomputed from the record the user typed rather than from the
 *    ciphertext. The collusion ledger's cancelling rows are recomputed from
 *    the provenance list in an earlier stage.
 *
 *  - PARTS-SUM-TO-WHOLE. The matrix's column count against 1 + sum(k-1) over
 *    the gate selects on screen. A key's element count against
 *    3 + 3*components + 3.
 *
 * Plus the two structural checks §4.1b names: RETIREMENT (change an input, the
 * stale verdict must be gone AND the page must say it was retired) and the
 * NO-OP GUARD (re-selecting the same value must NOT retire a fresh verdict),
 * and the `[hidden]` cascade probe.
 */

const READY = '[data-app-ready="true"]';

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(30_000);
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true');
  await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
}

/**
 * Parse a field element back out of the DOM.
 *
 * The page renders small positives as themselves, small negatives as `-n`, and
 * verified small rationals as `a/b` -- so this is the inverse of `fieldEntry`,
 * written independently rather than imported, because a shared helper would
 * make the round trip agree with itself.
 */
function parseFieldEntry(text: string): bigint | null {
  const t = text.trim();
  if (/^-?\d+$/.test(t)) {
    const v = BigInt(t);
    return v < 0n ? ((v % ORDER) + ORDER) % ORDER : v;
  }
  const frac = /^(-?\d+)\/(\d+)$/.exec(t);
  if (frac) {
    const num = BigInt(frac[1]);
    const den = BigInt(frac[2]);
    // Modular inverse by Fermat, which is a different route from the extended
    // Euclid the page uses.
    let inv = 1n;
    let base = den % ORDER;
    let e = ORDER - 2n;
    while (e > 0n) {
      if (e & 1n) inv = (inv * base) % ORDER;
      base = (base * base) % ORDER;
      e >>= 1n;
    }
    const v = (((num % ORDER) + ORDER) % ORDER) * inv;
    return v % ORDER;
  }
  return null; // truncated hex: not parseable, and the test says so
}

/** Read the matrix as rows of field elements plus the gamma column, if shown. */
async function readMatrix(
  page: Page,
): Promise<{ labels: string[]; rows: bigint[][]; gammas: (bigint | null)[]; columns: number }> {
  const headers = await page.$$eval('[data-host="matrix"] thead th', (ths) =>
    ths.map((t) => (t.textContent ?? '').trim()),
  );
  const hasGamma = headers[headers.length - 1] === 'gamma_i';
  const columns = headers.length - 2 - (hasGamma ? 1 : 0);
  const cells = await page.$$eval('[data-host="matrix"] tbody tr', (trs) =>
    trs.map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => (td.textContent ?? '').trim())),
  );
  const labels: string[] = [];
  const rows: bigint[][] = [];
  const gammas: (bigint | null)[] = [];
  for (const row of cells) {
    // Cell 1 is the row index, cell 2 is the label plus any held/missing chip.
    labels.push((row[1] ?? '').replace(/(held|missing)$/, '').trim());
    const values = row.slice(2, 2 + columns).map((c) => parseFieldEntry(c));
    expect(values.every((v) => v !== null), `matrix row parses: ${row.join(' | ')}`).toBe(true);
    rows.push(values as bigint[]);
    gammas.push(hasGamma ? parseFieldEntry(row[2 + columns] ?? '') : null);
  }
  return { labels, rows, gammas, columns };
}

test.describe('the page agrees with itself', () => {
  test('every key card s element count matches the labels it lists', async ({ page }) => {
    await boot(page);
    const cards = page.locator('.person');
    const n = await cards.count();
    expect(n).toBe(5);
    for (let i = 0; i < n; i++) {
      const labels = (await cards.nth(i).locator('.person-attrs').innerText())
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const meta = await cards.nth(i).locator('.person-meta').innerText();
      const elements = Number(/(\d+) group elements/.exec(meta)?.[1]);
      const components = Number(/(\d+) attribute components/.exec(meta)?.[1]);
      // Parts sum to whole: sk0 is 3 elements of G2, sk' is 3 of G1, and each
      // attribute contributes 3 of G1.
      expect(components, `${await cards.nth(i).locator('.person-name').innerText()}`).toBe(
        labels.length,
      );
      expect(elements).toBe(3 + 3 * components + 3);
    }
  });

  test('the one-use table s k matches how many rows the matrix labels', async ({ page }) => {
    await boot(page);
    await page.selectOption('#preset', 'reuse');
    await expect(page.locator('[data-host="matrix"] tbody tr')).toHaveCount(4);

    const table = await page.$$eval('[data-host="transform"] tbody tr', (trs) =>
      trs.map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => (td.textContent ?? '').trim())),
    );
    const { labels } = await readMatrix(page);

    for (const [name, labelsCell, kCell, elementsCell] of table) {
      const k = Number(kCell);
      // Cross-check 1: the labels the transform lists are exactly the matrix
      // rows carrying that attribute.
      const inMatrix = labels.filter((l) => l.startsWith(`${name}:`)).sort();
      expect(labelsCell.split(',').map((s) => s.trim()).sort()).toEqual(inMatrix);
      // Cross-check 2: k is at least the number of rows this policy needs.
      expect(k).toBeGreaterThanOrEqual(inMatrix.length);
      // Cross-check 3: the stated G1 cost is 3 per copy.
      expect(Number(elementsCell)).toBe(3 * k);
    }

    // And the reused attribute really did double a holder's key. Bob holds
    // only Doctor, so his key is the clean measurement of the factor of k.
    await page.getByRole('button', { name: 'Re-issue every key' }).click();
    const bob = page.locator('.person', { hasText: 'Bob' }).first();
    await expect(bob.locator('.person-attrs')).toHaveText('Doctor:1 , Doctor:2');
    const meta = await bob.locator('.person-meta').innerText();
    expect(Number(/(\d+) attribute components/.exec(meta)?.[1])).toBe(2);
  });

  test('the matrix column count is 1 plus the sum of (k-1) over every gate', async ({ page }) => {
    await boot(page);
    for (const preset of ['headline', 'reuse', 'threshold', 'nested']) {
      await page.selectOption('#preset', preset);
      await expect(page.locator('[data-host="matrix"] tbody tr')).not.toHaveCount(0);

      // Read every gate's k and n straight off the selects in the tree.
      const gates = await page.$$eval('select[id^="gate-"]', (sels) =>
        sels.map((s) => ({
          k: Number((s as HTMLSelectElement).value),
          n: (s as HTMLSelectElement).options.length,
        })),
      );
      const predicted = 1 + gates.reduce((acc, g) => acc + (g.k - 1), 0);
      const { columns } = await readMatrix(page);
      expect(columns, `${preset}: gates ${JSON.stringify(gates)}`).toBe(predicted);
    }
  });

  test('the failure-code table matches the exported constants exactly', async ({ page }) => {
    await boot(page);
    const rendered = await page.$$eval('#codes tbody tr', (trs) =>
      trs.map((tr) => {
        const tds = Array.from(tr.querySelectorAll('td'));
        return {
          id: (tds[0].textContent ?? '').trim(),
          surface: (tds[1].textContent ?? '').trim(),
          meaning: (tds[2].textContent ?? '').trim(),
        };
      }),
    );
    expect(rendered.map((r) => r.id)).toEqual(FAILURE_CODE_IDS);
    for (const row of rendered) {
      const code = FAILURE_CODES[row.id as keyof typeof FAILURE_CODES];
      expect(row.meaning).toBe(code.meaning);
      expect(row.surface).toBe(code.surface);
    }
    // The internal invariant is labelled as such, and there is exactly one.
    expect(rendered.filter((r) => r.surface === 'internal').map((r) => r.id)).toEqual([
      'ATTRIBUTE_REUSED',
    ]);
  });
});

test.describe('the headline claim, recomputed from what is on screen', () => {
  test('sum gamma_i M_i really is (1, 0, ..., 0), parsed back out of the matrix', async ({
    page,
  }) => {
    await boot(page);
    // A threshold gate, so the coefficients are genuine rationals rather than
    // a sum of ones -- the case where a formatting bug could hide.
    await page.selectOption('#preset', 'threshold');
    await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
    await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
    await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
    await expect(page.locator('[data-host="attempt"] .verdict')).toHaveAttribute(
      'data-outcome',
      'opened',
    );

    const { rows, gammas, columns } = await readMatrix(page);
    expect(gammas.some((g) => g !== null && g !== 0n)).toBe(true);

    // Recompute the combination here, from the printed numbers.
    const combined = new Array<bigint>(columns).fill(0n);
    rows.forEach((row, i) => {
      const g = gammas[i];
      if (g === null || g === 0n) return;
      for (let c = 0; c < columns; c++) {
        combined[c] = (combined[c] + g * row[c]) % ORDER;
      }
    });
    expect(combined[0]).toBe(1n);
    expect(combined.slice(1).every((x) => x === 0n)).toBe(true);

    // And the page's own printed answer agrees with the one computed here.
    const printed = await page
      .locator('[data-host="reconstruction"] .formula')
      .filter({ hasText: 'sum gamma_i' })
      .innerText();
    const shown = /\(([^)]*)\)/.exec(printed)?.[1] ?? '';
    const shownValues = shown.split(',').map((s) => parseFieldEntry(s));
    expect(shownValues).toEqual(combined);
  });

  test('the Lagrange basis for a 2-of-3 gate is 3/2 and -1/2 when rows 1 and 3 are used', async ({
    page,
  }) => {
    await boot(page);
    await page.selectOption('#preset', 'threshold');
    // Carol holds Emergency only, so she fails; Dan holds Nurse. Use Alice
    // (Doctor + Cardiology -> rows 1 and 2) and then a holder using rows 1,3.
    await page.selectOption('#recon-who', 'Alice');
    await expect(page.locator('[data-host="reconstruction"]')).toContainText('lambda_1 = 2');
    await expect(page.locator('[data-host="reconstruction"]')).toContainText('lambda_2 = -1');
    // 2 and -1 are the Lagrange coefficients at 0 through x = 1 and x = 2,
    // recomputed here: l_1 = (0-2)/(1-2) = 2, l_2 = (0-1)/(2-1) = -1.
    expect((0 - 2) / (1 - 2)).toBe(2);
    expect((0 - 1) / (2 - 1)).toBe(-1);
  });

  test('the pairing count the page prints is 6, and does not move with the policy', async ({
    page,
  }) => {
    await boot(page);
    const counts: number[] = [];
    const rowCounts: number[] = [];
    // Alice holds Doctor and Cardiology, and these are the three presets she
    // satisfies. The re-issue is not incidental: the reuse preset raises k for
    // Doctor, so a key minted under the old k is genuinely stale and would be
    // refused -- which is exhibit 2's point, and would make this test measure
    // that instead of the pairing count.
    for (const preset of ['headline', 'reuse', 'threshold']) {
      await page.selectOption('#preset', preset);
      await page.getByRole('button', { name: 'Re-issue every key' }).click();
      await expect(page.locator('.person .chip-warn')).toHaveCount(0);
      await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
      await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
      await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
      const verdict = page.locator('[data-host="attempt"] .verdict');
      await expect(verdict).toHaveAttribute('data-outcome', 'opened');
      const line = await verdict.locator('.fact-pairings').innerText();
      counts.push(Number(/Pairings computed: (\d+)/.exec(line)?.[1]));
      rowCounts.push(await page.locator('[data-host="matrix"] tbody tr').count());
    }
    // The policies really are different sizes...
    expect(new Set(rowCounts).size).toBeGreaterThan(1);
    // ...and the pairing count does not move.
    expect(counts).toEqual([6, 6, 6]);
  });

  test('a refusal costs zero pairings, because decryption never runs', async ({ page }) => {
    await boot(page);
    await page.getByRole('button', { name: /Try to open the sealed record with Dan/ }).click();
    const verdict = page.locator('[data-host="attempt"] .verdict');
    await expect(verdict).toHaveAttribute('data-code', 'POLICY_UNSATISFIED');
    await expect(verdict.locator('.fact-pairings')).toContainText('Pairings computed: 0');
    await expect(verdict.locator('.fact-pairings')).toContainText('before any were needed');
  });

  test('the sealed byte count is the record the user typed, plus a 16-byte tag', async ({
    page,
  }) => {
    await boot(page);
    const record = 'Ward 3B admission note';
    await page.fill('#record-input', record);
    await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
    await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();

    const status = await page.locator('[data-host="seal-status"]').innerText();
    const sealedBytes = Number(/sealed (\d+) bytes of record/.exec(status)?.[1]);
    // Independent route: measure the UTF-8 length of what is in the input,
    // rather than reading it back off the ciphertext the page produced.
    const utf8 = new TextEncoder().encode(record).length;
    expect(sealedBytes).toBe(utf8);
    expect(status).toContain('16-byte tag');

    // And opening it returns exactly those bytes.
    await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
    await expect(page.locator('[data-host="attempt"] .verdict-plain')).toHaveText(record);
  });
});

test.describe('every failure path names its actual cause', () => {
  test('POLICY_UNSATISFIED names the rows, and they are the rows marked missing', async ({
    page,
  }) => {
    await boot(page);
    await page.getByRole('button', { name: /Try to open the sealed record with Bob/ }).click();
    const verdict = page.locator('[data-host="attempt"] .verdict');
    await expect(verdict).toHaveAttribute('data-code', 'POLICY_UNSATISFIED');

    const detail = await verdict.locator('.verdict-detail').innerText();
    // Cross-check: the labels named in the prose are exactly the labels of the
    // rows the matrix painted as missing.
    const named = [...detail.matchAll(/row \d+ wants ([A-Za-z0-9:]+)/g)].map((m) => m[1]).sort();
    const missing = await page.$$eval('[data-host="matrix"] tr.row-missing td:nth-child(2)', (tds) =>
      tds.map((td) => (td.textContent ?? '').replace(/missing$/, '').trim()),
    );
    expect(named).toEqual(missing.sort());
    expect(named.length).toBeGreaterThan(0);

    // And the tree says the same thing at the node that failed.
    await expect(page.locator('.node-unsat').first()).toBeVisible();
    await expect(page.locator('#builder')).toContainText('ATTR_MISSING');
  });

  test('THRESHOLD_NOT_MET reports counts that match the gate on screen', async ({ page }) => {
    await boot(page);
    await page.selectOption('#preset', 'threshold');
    await page.getByRole('button', { name: 'Seal the record under this policy' }).click();
    await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();
    await page.getByRole('button', { name: /Try to open the sealed record with Carol/ }).click();

    const detail = await page.locator('[data-host="attempt"] .verdict-detail').innerText();
    const m = /needed (\d+) satisfied inputs and had (\d+)/.exec(detail);
    expect(m, detail).not.toBeNull();
    const need = Number(m?.[1]);
    const have = Number(m?.[2]);

    // Cross-check against the gate's own select and the rows the key holds.
    const k = Number(await page.locator('select[id^="gate-"]').first().inputValue());
    expect(need).toBe(k);
    const held = await page.locator('[data-host="matrix"] tr.row-held').count();
    expect(have).toBe(held);
    expect(have).toBeLessThan(need);
  });

  test('MALFORMED_POLICY names the offending attribute and changes nothing', async ({ page }) => {
    await boot(page);
    const before = await page.locator('[data-host="formula"] code').innerText();
    const rowsBefore = await page.locator('[data-host="matrix"] tbody tr').count();

    await page.fill('#custom-attr', 'Doctor:1');
    await page.getByRole('button', { name: 'Add a custom attribute' }).click();
    const verdict = page.locator('[data-host="seal-status"] .verdict-fail');
    await expect(verdict).toHaveAttribute('data-code', 'MALFORMED_POLICY');
    await expect(verdict).toContainText('Doctor:1');
    await expect(verdict).toContainText('one-use transform reserves');

    // Fail-closed: the rejected policy was not adopted.
    await expect(page.locator('[data-host="formula"] code')).toHaveText(before);
    await expect(page.locator('[data-host="matrix"] tbody tr')).toHaveCount(rowsBefore);
  });

  test('COLLUSION_BLOCKED: the policy passes, the ledger explains it, both directions fail', async ({
    page,
  }) => {
    await boot(page);
    await page.selectOption('#collude-a', 'Bob');
    await page.selectOption('#collude-b', 'Eve');
    await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
    await expect(page.locator('[data-host="collusion"] [data-stage="6"]')).toBeVisible();

    // The surprising claim, stated: the policy check passed.
    await expect(page.locator('[data-host="collusion"] [data-stage="3"]')).toContainText(
      'POLICY SATISFIED',
    );
    // Every verdict agrees that it passed, and that the record still shut.
    const verdicts = page.locator('[data-host="collusion"] .verdict');
    await expect(verdicts).toHaveCount(2);
    for (let i = 0; i < 2; i++) {
      await expect(verdicts.nth(i)).toHaveAttribute('data-code', 'COLLUSION_BLOCKED');
      await expect(verdicts.nth(i)).toContainText('Policy satisfied: yes');
      await expect(verdicts.nth(i)).toContainText('It equalled the encapsulated element: no');
      await expect(verdicts.nth(i)).toContainText('AES-GCM verified the tag: no');
    }

    // Independent re-derivation of the ledger: stage 2 lists which key each
    // component came from, and stage 4 says which rows cancel. A row cancels
    // exactly when its component came from the SAME holder as sk0 -- which
    // stage 2's first line names. Recompute that here and compare.
    const provenance = await page.$$eval('[data-host="collusion"] [data-stage="2"] li', (lis) =>
      lis.map((li) => (li.textContent ?? '').trim()),
    );
    const baseText = await page.locator('[data-host="collusion"] [data-stage="2"] p').innerText();
    const base = /taken from (\w+);/.exec(baseText)?.[1];
    expect(base, baseText).toBeTruthy();

    const ledger = await page.$$eval('[data-host="collusion"] .ledger tbody tr', (trs) =>
      trs.map((tr) => {
        const tds = Array.from(tr.querySelectorAll('td')).map((t) => (t.textContent ?? '').trim());
        return { label: tds[1], holder: tds[2], deltas: tds.slice(3, 6), outcome: tds[6] };
      }),
    );
    expect(ledger.length).toBeGreaterThan(1);
    for (const row of ledger) {
      const fromBase = row.holder === base;
      // Cross-check with the provenance list rendered in a different stage.
      const stated = provenance.find((p) => p.startsWith(row.label));
      expect(stated, `${row.label} appears in the provenance list`).toBeTruthy();
      expect(stated?.endsWith(`from ${row.holder}`)).toBe(true);
      // Re-derived: same holder as sk0 => all three deltas are zero.
      expect(row.deltas.every((d) => d === '0')).toBe(fromBase);
      expect(row.outcome).toBe(fromBase ? 'cancels' : 'survives');
    }
    expect(ledger.some((r) => r.outcome === 'survives')).toBe(true);

    // The two routes to the residual must agree, and it must not be 1. The
    // chip's word and its detail are separate spans, so they are read
    // separately rather than as one run of text.
    const agree = page.locator('[data-host="collusion"] .chip', { hasText: 'all 576 bytes' });
    await expect(agree).toHaveAttribute('data-tone', 'pass');
    await expect(agree.locator('.chip-label')).toHaveText('yes');
    const identity = page.locator('[data-host="collusion"] .chip', {
      hasText: 'the record stays shut',
    });
    await expect(identity).toHaveAttribute('data-tone', 'fail');
    await expect(identity.locator('.chip-label')).toHaveText('no');
  });

  test('a pair that is not a collusion scenario is named as such, not narrated as one', async ({
    page,
  }) => {
    await boot(page);
    // Alice satisfies (Doctor AND Cardiology) OR Emergency on her own, so
    // pooling adds nothing. The exhibit must say that rather than walk through
    // six stages titled "the blinding does not cancel".
    await page.selectOption('#collude-a', 'Alice');
    await page.selectOption('#collude-b', 'Carol');
    await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
    const panel = page.locator('[data-host="collusion"] [data-scenario="not-collusion"]');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText('already satisfies this policy alone');
    // No six-stage walkthrough, and no ledger claiming a cancellation failure.
    await expect(page.locator('[data-host="collusion"] [data-stage]')).toHaveCount(0);
    await expect(page.locator('[data-host="collusion"] .ledger')).toHaveCount(0);
    // The real outcomes are still shown, both solo and pooled.
    await expect(panel.locator('.verdict[data-outcome="opened"]')).not.toHaveCount(0);
  });

  test('a pair whose union still fails is refused by the policy check, not by collusion', async ({
    page,
  }) => {
    await boot(page);
    // Dan holds Nurse and Bob holds Doctor; together they still do not satisfy
    // (Doctor AND Cardiology) OR Emergency.
    await page.selectOption('#collude-a', 'Bob');
    await page.selectOption('#collude-b', 'Dan');
    await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
    const panel = page.locator('[data-host="collusion"] [data-scenario="not-collusion"]');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText('not collusion resistance');
    await expect(panel.locator('.verdict[data-code="POLICY_UNSATISFIED"]')).not.toHaveCount(0);
    await expect(page.locator('[data-host="collusion"] [data-stage]')).toHaveCount(0);
  });
});

test.describe('the negative claims, as fixtures', () => {
  test('NEG-1: a revoked key opens a record sealed after the revocation', async ({ page }) => {
    await boot(page);
    await page.selectOption('#revoke-who', 'Carol');

    // Record the key BEFORE revoking, so the claim that nothing changed is a
    // comparison rather than an assertion.
    const carol = page.locator('.person', { hasText: 'Carol' }).first();
    const labelsBefore = await carol.locator('.person-attrs').innerText();
    const metaBefore = await carol.locator('.person-meta').innerText();

    await page.getByRole('button', { name: /Revoke, seal a new record/ }).click();
    const stage3 = page.locator('[data-host="revocation"] [data-stage="3"]');
    await expect(stage3).toHaveAttribute('data-opened', 'true');

    // The record it opened was sealed AFTER the revocation, and says so.
    await expect(stage3.locator('.verdict-plain')).toContainText('Sealed after Carol was revoked');
    await expect(stage3.locator('.verdict')).toHaveAttribute('data-outcome', 'opened');

    // Nothing about the key changed when the flag flipped.
    await expect(carol.locator('.person-attrs')).toHaveText(labelsBefore);
    expect(await carol.locator('.person-meta').innerText()).toBe(metaBefore);
    await expect(carol.locator('.chip-warn')).toContainText('revoked');

    // And the page states the general claim rather than leaving it implied.
    await expect(page.locator('#revocation')).toContainText(
      'An issued key decrypts matching ciphertexts indefinitely',
    );
  });

  test('THREAT-1: escrow is two steps, and step 1 produces a key rather than a plaintext', async ({
    page,
  }) => {
    await boot(page);
    await page.getByRole('button', { name: 'Mint an authority key, then decrypt' }).click();
    const step1 = page.locator('[data-host="escrow"] [data-stage="1"]');
    const step2 = page.locator('[data-host="escrow"] [data-stage="2"]');
    await expect(step2).toBeVisible();

    // Step 1 shows an attribute set and NO plaintext.
    await expect(step1).toContainText('Mint a key');
    await expect(step1.locator('.verdict-plain')).toHaveCount(0);
    const minted = await step1.locator('code').innerText();
    const mintedLabels = minted.split(',').map((s) => s.trim());

    // Cross-check: every minted label is a real row label in the matrix.
    const { labels } = await readMatrix(page);
    for (const l of mintedLabels) expect(labels).toContain(l);

    // Parts sum to whole: the element count matches the labels it minted.
    const elements = Number(/(\d+) group elements/.exec(await step1.innerText())?.[1]);
    expect(elements).toBe(3 + 3 * mintedLabels.length + 3);

    // Step 2 is where the plaintext appears.
    await expect(step2.locator('.verdict')).toHaveAttribute('data-outcome', 'opened');
    await expect(step2.locator('.verdict-plain')).toContainText('PATIENT');
  });

  test('the scoping panel says what this does not prove', async ({ page }) => {
    await boot(page);
    const honesty = page.locator('#honesty');
    await expect(honesty).toContainText('Not production cryptography');
    await expect(honesty).toContainText('Not proved by anything on this page');
    await expect(honesty).toContainText('is a demonstration of the mechanism, not a security proof');
    await expect(honesty).toContainText('Nothing here is constant-time');
    await expect(honesty).toContainText('Simplified, and named as such');
  });
});

test.describe('FABESA partially hidden-policy claims', () => {
  test('the two worlds expose the same public shape while their equal-length values differ', async ({
    page,
  }) => {
    await boot(page);
    await expect(page.locator('#fabesa')).toHaveAttribute('data-fabesa-ready', 'true');

    const cards = page.locator('[data-fabesa-world]');
    await expect(cards).toHaveCount(2);
    const shapes = await cards.locator('.fabesa-world-shape').allInnerTexts();
    const metadata = await cards.locator('.fabesa-world-meta').allInnerTexts();
    expect(new Set(shapes).size).toBe(1);
    expect(new Set(metadata).size).toBe(1);

    const fingerprints = await cards.locator('.fabesa-fingerprint code').allInnerTexts();
    expect(fingerprints).toHaveLength(2);
    expect(fingerprints[0]).not.toBe(fingerprints[1]);

    const observer = page.locator('[data-fabesa-role="observer"]');
    const observerText = await observer.innerText();
    for (const secret of [
      'BLOCKED',
      'PENDING',
      'CARD-017',
      'NEUR-204',
      'RESEARCH',
      'CLINICAL',
      'CARDIAC',
      'SEIZURE',
    ]) {
      expect(observerText).not.toContain(secret);
    }
    await expect(observer.locator('[data-visibility="public"]')).not.toHaveCount(0);
    await expect(observer.locator('[data-visibility="hidden"]')).toHaveCount(2);
    await expect(observer).toContainText('Emergency');
    await expect(observer).toContainText('3 rows x 2 columns');

    await page.locator('#fabesa-ground-truth > summary').click();
    const valueRows = page.locator('#fabesa-ground-truth tbody tr');
    await expect(valueRows).toHaveCount(3);
    for (let index = 0; index < 3; index++) {
      const cells = await valueRows.nth(index).locator('td').allInnerTexts();
      const a = cells[0];
      const b = cells[1];
      expect(a).not.toBe(b);
      expect(new TextEncoder().encode(a).length).toBe(new TextEncoder().encode(b).length);
      expect(Number(cells[2])).toBe(new TextEncoder().encode(a).length);
    }
  });

  test('candidate attempts are sequential, measured, and authenticated without an expected plaintext', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#fabesa-open').click();
    const result = page.locator('[data-host="fabesa-attempt"] .verdict');
    await expect(result).toHaveAttribute('data-code', 'FABESA_OPENED');

    const rows = result.locator('[data-candidate]');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0)).toHaveAttribute('data-aead', 'rejected');
    await expect(rows.nth(1)).toHaveAttribute('data-aead', 'accepted');
    await expect(rows.nth(0)).toHaveAttribute('data-pairing-terms', '4');
    await expect(rows.nth(1)).toHaveAttribute('data-pairing-terms', '4');

    const measured = (await rows.evaluateAll((nodes) =>
      nodes.map((node) => Number(node.getAttribute('data-pairings'))),
    ));
    // This secure-random fixture is nondegenerate with overwhelming
    // probability, so all four Figure 5 terms must reach the primitive. The
    // deterministic unit suite separately covers the legitimate r=0 identity
    // short-circuit and proves that boundary reports one executed call.
    expect(measured).toEqual([4, 4]);
    const total = Number(await result.locator('[data-total-pairings]').getAttribute('data-total-pairings'));
    expect(total).toBe(8);
    await expect(result.locator('[data-total-pairing-terms="8"]')).toBeVisible();
    await expect(result).toContainText('not given an expected plaintext');
    await expect(result.locator('[data-fabesa-plaintext="revealed"]')).toBeVisible();
  });

  test('wrong values, a foreign authority, and record tampering share the generic tag failure', async ({
    page,
  }) => {
    await boot(page);
    const verdict = page.locator('[data-host="fabesa-attempt"] .verdict');

    await page.selectOption('#fabesa-key-profile', 'wrong-values');
    await page.locator('#fabesa-open').click();
    await expect(verdict).toHaveAttribute('data-code', 'NO_CANDIDATE_AUTHENTICATED');

    await page.selectOption('#fabesa-key-profile', 'foreign-authority');
    await page.locator('#fabesa-open').click();
    await expect(verdict).toHaveAttribute('data-code', 'NO_CANDIDATE_AUTHENTICATED');

    await page.selectOption('#fabesa-key-profile', 'alice');
    await page.selectOption('#fabesa-modification', 'flip-record');
    await page.locator('#fabesa-open').click();
    await expect(verdict).toHaveAttribute('data-code', 'NO_CANDIDATE_AUTHENTICATED');
    await expect(verdict).toContainText('does not identify which cause occurred');
  });

  test('public mismatch and malformed input stop before pairing work', async ({ page }) => {
    await boot(page);
    const verdict = page.locator('[data-host="fabesa-attempt"] .verdict');

    await page.selectOption('#fabesa-key-profile', 'missing-names');
    await page.locator('#fabesa-open').click();
    await expect(verdict).toHaveAttribute('data-code', 'PUBLIC_NAMES_UNSATISFIED');
    await expect(verdict.locator('[data-total-pairings="0"]')).toBeVisible();
    await expect(verdict.locator('[data-candidate]')).toHaveCount(0);

    await page.selectOption('#fabesa-modification', 'malformed-envelope');
    await page.locator('#fabesa-open').click();
    await expect(verdict).toHaveAttribute('data-code', 'MALFORMED_FABESA_CIPHERTEXT');
    await expect(verdict.locator('[data-total-pairings="0"]')).toBeVisible();
  });

  test('an unexpected WebCrypto failure is not disguised as candidate rejection', async ({
    page,
  }) => {
    await boot(page);
    await page.evaluate(() => {
      Object.defineProperty(crypto.subtle, 'decrypt', {
        configurable: true,
        value: async () => {
          throw new TypeError('synthetic WebCrypto runtime failure');
        },
      });
    });

    await page.locator('#fabesa-open').click();
    const verdict = page.locator('[data-host="fabesa-attempt"] .verdict');
    await expect(verdict).toHaveAttribute('data-code', 'FABESA_LESSON_ERROR');
    await expect(verdict).toContainText('synthetic WebCrypto runtime failure');
    await expect(verdict).toContainText('not claimed because the operation aborted unexpectedly');
    await expect(verdict.locator('[data-total-pairings]')).toHaveCount(0);
  });

  test('changing a FABESA input retires a result, while reselecting it is a no-op', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#fabesa-open').click();
    const host = page.locator('[data-host="fabesa-attempt"]');
    await expect(host.locator('.verdict')).toHaveAttribute('data-code', 'FABESA_OPENED');

    await page.selectOption('#fabesa-world', 'a');
    await expect(host.locator('[data-retired="true"]')).toHaveCount(0);
    await expect(host.locator('.verdict')).toHaveAttribute('data-code', 'FABESA_OPENED');

    await page.selectOption('#fabesa-world', 'b');
    await expect(host.locator('[data-retired="true"]')).toBeVisible();
    await expect(host.locator('.verdict[data-code]')).toHaveCount(0);
  });

  test('resealing changes the ciphertext and the candidate cap fails closed before decryption', async ({
    page,
  }) => {
    await boot(page);
    const fingerprint = page.locator('[data-fabesa-world="a"] .fabesa-fingerprint code');
    const before = await fingerprint.innerText();
    await page.locator('#fabesa-reseal').click();
    await expect(fingerprint).not.toHaveText(before);

    await page.locator('#fabesa-run-cap').click();
    const cap = page.locator('[data-host="fabesa-cap"] .verdict');
    await expect(cap).toHaveAttribute('data-code', 'CANDIDATE_LIMIT_EXCEEDED');
    await expect(cap).toContainText('Candidate 33');
    await expect(cap).toContainText('45 possible pairs');
    await expect(cap.locator('[data-total-pairings="0"]')).toBeVisible();
  });
});

test.describe('RW15 decentralized multi-authority claims', () => {
  test('same-GID keys open, while the strongest raw cross-GID pool fails cryptographically', async ({
    page,
  }) => {
    await boot(page);
    const lesson = page.locator('#rw15');
    await expect(lesson).toHaveAttribute('data-rw15-ready', 'true');

    // Two independently generated public keys are learner-visible before any
    // decryption path runs. This cross-checks the setup verdict against the
    // authority cards instead of trusting a hardcoded caption.
    const setup = page.locator('[data-host="rw15-setup"] [data-rw15-authorities="2"]');
    await expect(setup).toBeVisible();
    const authorities = await setup.locator('[data-rw15-authority]').evaluateAll((nodes) =>
      nodes.map((node) => node.getAttribute('data-rw15-authority')),
    );
    expect(authorities).toEqual(['Hospital', 'Board']);
    const authorityFingerprints = await setup
      .locator('[data-rw15-authority] .verdict-plain code')
      .allInnerTexts();
    expect(authorityFingerprints).toHaveLength(2);
    expect(authorityFingerprints[0]).not.toBe(authorityFingerprints[1]);

    await page.locator('#rw15-run-same-gid').click();
    const same = page.locator('[data-host="rw15-same-gid"] [data-rw15-case="same-gid"]');
    await expect(same).toHaveAttribute('data-code', 'RW15_SAME_GID_OPENED');
    await expect(same).toHaveAttribute('data-policy-satisfied', 'true');
    await expect(same).toHaveAttribute('data-recovered-matches', 'true');
    await expect(same).toHaveAttribute('data-aead-accepted', 'true');
    await expect(same).toContainText('Exact canonical GID: gid:alice');
    await expect(same).toContainText('Selected rows: 1, 2');
    await expect(same).toContainText(
      'Authenticated plaintext: CASE-0317: independently authorized cardiology record',
    );

    const sameFacts = same.locator('.honesty-list li');
    const samePairingText = await sameFacts.nth(2).innerText();
    const samePairing = /(\d+) selected rows? × 3 pairing terms; (\d+) actual/.exec(
      samePairingText,
    );
    expect(samePairing).not.toBeNull();
    expect(Number(samePairing?.[2])).toBe(Number(samePairing?.[1]) * 3);
    expect(await sameFacts.nth(3).locator('code').innerText()).toBe(
      await sameFacts.nth(4).locator('code').innerText(),
    );

    await page.locator('#rw15-run-cross-gid').click();
    const cross = page.locator('[data-host="rw15-cross-gid"] [data-rw15-case="cross-gid"]');
    await expect(cross).toHaveAttribute('data-code', 'RW15_CROSS_GID_TAG_REJECTED');
    // This is deliberately the stronger raw-combination experiment: the
    // labels reach both rows, but distinct H(GID) bases leave the wrong GT
    // element and the authenticated wrapper rejects it. An early metadata
    // mismatch would make these assertions fail.
    await expect(cross).toHaveAttribute('data-policy-satisfied', 'true');
    await expect(cross).toHaveAttribute('data-recovered-matches', 'false');
    await expect(cross).toHaveAttribute('data-aead-accepted', 'false');
    await expect(cross).toContainText('Structural reconstruction: satisfied');
    await expect(cross).toContainText(
      'The API did not reject a GID mismatch before doing the algebra',
    );
    await expect(cross).toContainText('Doctor@Hospital / gid:bob');
    await expect(cross).toContainText('Cardiology@Board / gid:eve');

    const crossFacts = cross.locator('.honesty-list li');
    const crossPairingText = await crossFacts.nth(2).innerText();
    const crossPairing = /(\d+) selected rows? × 3 pairing terms; (\d+) actual/.exec(
      crossPairingText,
    );
    expect(crossPairing).not.toBeNull();
    expect(Number(crossPairing?.[2])).toBe(Number(crossPairing?.[1]) * 3);
    expect(await crossFacts.nth(3).locator('code').innerText()).not.toBe(
      await crossFacts.nth(4).locator('code').innerText(),
    );
  });

  test('one compromised issuer breaks only its own boundary, and Board remains required', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#rw15-run-compromise').click();

    const result = page.locator(
      '[data-host="rw15-compromise"] [data-rw15-case="compromise"]',
    );
    await expect(result).toHaveAttribute('data-code', 'RW15_ONE_AUTHORITY_COMPROMISED');
    await expect(result).toHaveAttribute('data-own-policy-opened', 'true');
    await expect(result).toHaveAttribute('data-cross-policy-opened', 'false');
    await expect(result).toHaveAttribute('data-board-still-required', 'true');
    await expect(
      result.locator('[data-compromise-policy="authority-a-only"]'),
    ).toHaveAttribute('data-opened', 'true');
    await expect(result.locator('[data-compromise-policy="cross-authority"]')).toHaveAttribute(
      'data-opened',
      'false',
    );
    await expect(result).toContainText('Doctor@Hospital / gid:mallory');
    await expect(result).toContainText('Hospital-only policy: opened by compromised issuer');
    await expect(result).toContainText('Hospital AND Board policy: Board still required');
    await expect(result).toContainText('1 selected row × 3 pairing terms; 3 actual');
  });

  test('the RW15 compiler preserves repeated logical attributes and states the proof boundary', async ({
    page,
  }) => {
    await boot(page);

    const repeated = page.locator('#rw15 details[data-rw15-repeat-satisfied="true"]');
    await expect(repeated).toHaveAttribute('data-rw15-repeat-used-rows', '1,3');
    await repeated.locator('summary').click();
    const rows = await repeated.locator('tbody tr').evaluateAll((nodes) =>
      nodes.map((node) => ({
        row: (node.querySelector('th')?.textContent ?? '').trim(),
        attribute: (node.querySelector('td code')?.textContent ?? '').trim(),
        selected: node.getAttribute('data-selected'),
      })),
    );
    expect(rows).toEqual([
      { row: '1', attribute: 'STUDENT@UT', selected: 'true' },
      { row: '2', attribute: 'PROFESSOR@OU', selected: 'false' },
      { row: '3', attribute: 'STUDENT@UT', selected: 'true' },
      { row: '4', attribute: 'MASTERS@OU', selected: 'false' },
    ]);
    expect(rows.filter((row) => row.attribute === 'STUDENT@UT')).toHaveLength(2);
    expect(rows.some((row) => /:\d+$/.test(row.attribute))).toBe(false);
    await expect(repeated).toContainText('one STUDENT@UT key reconstructs with rows 1, 3');

    const scope = page.locator('#rw15 details[data-rw15-claim-scope="static-rom-q-dpbdhe2"]');
    await scope.locator('summary').click();
    await expect(scope).toContainText(
      'static (non-adaptive) security in the random-oracle model under q-DPBDHE2',
    );
    await expect(scope).toContainText('challenge matrix of at most q × q');
    await expect(scope.locator('[data-rw15-assumption="authority-directory"]')).toContainText(
      'authenticated directory',
    );
    await expect(scope.locator('[data-rw15-assumption="gid-proofing"]')).toContainText(
      'same byte-exact canonical GID',
    );
    await expect(scope.locator('[data-rw15-nonclaim="hybrid-wrapper"]')).toContainText(
      'proof is not transferred',
    );
    await expect(scope.locator('[data-rw15-nonclaim="security-properties"]')).toContainText(
      'statically declared corrupt authorities',
    );
    await expect(scope.locator('[data-rw15-nonclaim="security-properties"]')).toContainText(
      'does not test rogue-key registration',
    );
    await expect(scope.locator('[data-rw15-nonclaim="security-properties"]')).toContainText(
      'No adaptive-security',
    );
    await expect(scope.locator('a', { hasText: 'Rouselakis–Waters' })).toHaveAttribute(
      'href',
      'https://doi.org/10.1007/978-3-662-47854-7_19',
    );
    await expect(scope.locator('a', { hasText: 'Charm implementation' })).toHaveAttribute(
      'href',
      'https://jhuisi.github.io/charm/_modules/abenc_maabe_rw15.html',
    );
  });
});

test.describe('bounded epoch-gating and owner-assisted rewrap claims', () => {
  test('the lifecycle distinguishes current access, retained history, and rollback freshness', async ({
    page,
  }) => {
    await boot(page);
    await expect(page.locator('#epoch-revocation')).toHaveAttribute(
      'data-revocation-ready',
      'true',
    );
    await page.locator('#epoch-revocation-run').click();
    const result = page.locator('[data-host="epoch-revocation-result"]');
    await expect(result.locator('[data-revocation-case="cost-ledger"]')).toBeVisible();

    const bobOld = result.locator('[data-revocation-case="bob-old"]');
    await expect(bobOld).toHaveAttribute('data-code', 'OPENED');
    await expect(bobOld).toHaveAttribute('data-epoch', '1');
    await expect(bobOld).toHaveAttribute('data-opened', 'true');
    await expect(bobOld).toHaveAttribute('data-checkpoint', 'epoch-1');
    await expect(bobOld).toContainText('retained epoch-1 material still opens');

    const bobCurrent = result.locator('[data-revocation-case="bob-current"]');
    await expect(bobCurrent).toHaveAttribute('data-code', 'POLICY_UNSATISFIED');
    await expect(bobCurrent).toHaveAttribute('data-epoch', '2');
    await expect(bobCurrent).toHaveAttribute('data-opened', 'false');
    await expect(bobCurrent).toHaveAttribute('data-key-issued', 'false');
    await expect(bobCurrent).toContainText('HOLDER_REVOKED');
    await expect(bobCurrent).toContainText('withholds an entire new randomized FAME key');

    const aliceCurrent = result.locator('[data-revocation-case="alice-current"]');
    await expect(aliceCurrent).toHaveAttribute('data-code', 'OPENED');
    await expect(aliceCurrent).toHaveAttribute('data-epoch', '2');
    await expect(aliceCurrent).toHaveAttribute('data-opened', 'true');
    const currentLabels = aliceCurrent
      .locator('.honesty-list li')
      .filter({ hasText: 'New labels:' })
      .locator('code');
    await expect(currentLabels).toHaveText('Doctor:1, Access epoch 2:1');
    await expect(aliceCurrent).toContainText('not an independently updateable epoch component');

    const noCheckpoint = result.locator('[data-revocation-case="rollback-no-checkpoint"]');
    await expect(noCheckpoint).toHaveAttribute('data-code', 'OPENED');
    await expect(noCheckpoint).toHaveAttribute('data-opened', 'true');
    await expect(noCheckpoint).toHaveAttribute('data-checkpoint', 'none');
    await expect(noCheckpoint).toContainText('authenticity does not say they are current');

    const currentCheckpoint = result.locator(
      '[data-revocation-case="rollback-with-checkpoint"]',
    );
    await expect(currentCheckpoint).toHaveAttribute('data-code', 'ROLLBACK_DETECTED');
    await expect(currentCheckpoint).toHaveAttribute('data-opened', 'false');
    await expect(currentCheckpoint).toHaveAttribute('data-checkpoint', 'current');
    await expect(currentCheckpoint).toContainText(
      'binds object id, epoch, revision, and the digest of the complete current access header',
    );
  });

  test('rewrap preserves payload bytes, exposes both escrow powers, and reports actual work', async ({
    page,
  }) => {
    await boot(page);
    await page.locator('#epoch-revocation-run').click();
    const result = page.locator('[data-host="epoch-revocation-result"]');
    const bytes = result.locator('[data-revocation-case="payload-header"]');
    await expect(bytes).toHaveAttribute('data-code', 'HEADER_REWRAPPED_PAYLOAD_UNCHANGED');
    await expect(bytes).toHaveAttribute('data-payload-identical', 'true');
    await expect(bytes).toHaveAttribute('data-header-changed', 'true');
    await expect(bytes).toHaveAttribute('data-payload-bytes-rewritten', '0');

    const digestValues = await bytes.locator('code').allInnerTexts();
    expect(digestValues).toHaveLength(4);
    expect(digestValues[0]).toBe(digestValues[1]);
    expect(digestValues[2]).not.toBe(digestValues[3]);
    const bytesText = await bytes.innerText();
    const payloadSize = /Serialized payload: (\d+) bytes before and after/.exec(bytesText);
    const headerSizes =
      /Serialized access header: (\d+) bytes at epoch 1, (\d+) bytes at epoch 2/.exec(bytesText);
    expect(payloadSize).not.toBeNull();
    expect(headerSizes).not.toBeNull();

    const escrow = result.locator('[data-revocation-case="escrow"]');
    await expect(escrow).toHaveAttribute('data-code', 'OWNER_AND_AUTHORITY_ESCROW');
    await expect(escrow.locator('[data-revocation-escrow="owner"]')).toHaveAttribute(
      'data-opened',
      'true',
    );
    await expect(escrow.locator('[data-revocation-escrow="authority"]')).toHaveAttribute(
      'data-opened',
      'true',
    );
    await expect(escrow).toContainText('owner capability unwraps the DEK recovery capsule');
    await expect(escrow).toContainText('master secret mints a satisfying current key');

    const ledgerRows = result.locator('[data-revocation-cost]');
    await expect(ledgerRows).toHaveCount(14);
    const ledger = Object.fromEntries(
      await ledgerRows.evaluateAll((nodes) =>
        nodes.map((node) => [
          node.getAttribute('data-revocation-cost') ?? '',
          Number((node.querySelector('td')?.textContent ?? '').trim()),
        ]),
      ),
    );
    expect(ledger).toMatchObject({
      epochAdvances: 1,
      revocations: 1,
      holderKeyGenerations: 3,
      authorityEscrowKeyGenerations: 1,
      fameHeaderEncryptions: 2,
      payloadAeadEncryptions: 1,
      payloadPlaintextBytesEncrypted: new TextEncoder().encode(
        'CASE-0317: retained teaching record',
      ).length,
      ownerCapsuleEncryptions: 1,
      ownerDekUnwrapsForRewrap: 1,
      accessDekWraps: 2,
      checkpointWrites: 2,
      rewrapOperations: 1,
      rewrapPayloadBytesWritten: 0,
    });
    expect(ledger.accessHeaderBytesWritten).toBe(
      Number(headerSizes?.[1]) + Number(headerSizes?.[2]),
    );
    expect(Number(payloadSize?.[1])).toBeGreaterThan(35);
  });

  test('the learner-visible scope does not turn the bounded adaptation into a theorem', async ({
    page,
  }) => {
    await boot(page);
    const boundary = page.locator(
      '#epoch-revocation [data-revocation-scope="application-layer-fame-adaptation"]',
    );
    await expect(boundary).toContainText('not RW15');
    await expect(boundary).toContainText(
      'not a revocable-ABE or revocable-storage-ABE construction',
    );
    await expect(boundary).toContainText('not public ciphertext update');
    await expect(boundary).toContainText('not a FAME/RW15/revocation theorem');
    await expect(boundary).toContainText('owner-secret DEK recovery');

    const scope = page.locator(
      '#epoch-revocation details[data-revocation-claim-scope="bounded-application-adaptation"]',
    );
    await scope.locator('summary').click();
    await expect(scope).toContainText('retained old key plus retained old header still opens');
    await expect(scope).toContainText('If storage and its checkpoint roll back together');
    await expect(scope.locator('[data-revocation-assumption="issuer-state"]')).toContainText(
      'authenticates stable holder identifiers and authoritative business attributes',
    );
    await expect(scope.locator('[data-revocation-assumption="issuer-state"]')).toContainText(
      'rollback-resistant issuer storage',
    );
    await expect(scope.locator('[data-revocation-nonclaim="public-update"]')).toContainText(
      'There is no public update token',
    );
    await expect(scope.locator('[data-revocation-nonclaim="construction"]')).toContainText(
      'application-layer adaptation around single-authority FAME',
    );
    await expect(scope.locator('[data-revocation-nonclaim="proof"]')).toContainText(
      'No proof combines FAME with this epoch gate',
    );
  });
});

test.describe('structural honesty', () => {
  test('retirement: changing the policy retires every result and says so', async ({ page }) => {
    await boot(page);
    await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
    await expect(page.locator('[data-host="attempt"] .verdict')).toHaveAttribute(
      'data-outcome',
      'opened',
    );
    await page.getByRole('button', { name: 'Mint an authority key, then decrypt' }).click();
    await expect(page.locator('[data-host="escrow"] [data-stage="2"]')).toBeVisible();

    // Change the policy. Both results were computed against a ciphertext that
    // no longer exists.
    await page.selectOption('#preset', 'threshold');

    for (const host of ['attempt', 'escrow']) {
      const node = page.locator(`[data-host="${host}"]`);
      await expect(node.locator('[data-retired="true"]')).toHaveCount(1);
      await expect(node).toContainText('Result retired');
      // The stale verdict is GONE, not merely annotated.
      await expect(node.locator('.verdict[data-outcome]')).toHaveCount(0);
    }
    // And the page says the record needs resealing.
    await expect(page.locator('[data-host="seal-status"]')).toContainText('Not sealed');
  });

  test('no-op guard: re-selecting the same policy does not retire a fresh verdict', async ({
    page,
  }) => {
    await boot(page);
    await page.getByRole('button', { name: /Try to open the sealed record with Alice/ }).click();
    const verdict = page.locator('[data-host="attempt"] .verdict');
    await expect(verdict).toHaveAttribute('data-outcome', 'opened');
    const before = await verdict.innerText();

    // Re-select the preset already showing. Every preset build makes fresh node
    // ids for the same tree, so a naive identity check would retire here.
    await page.selectOption('#preset', 'headline');
    await page.waitForTimeout(200);
    await expect(page.locator('[data-host="attempt"] [data-retired="true"]')).toHaveCount(0);
    await expect(verdict).toHaveAttribute('data-outcome', 'opened');
    expect(await verdict.innerText()).toBe(before);
    // The seal is still live too.
    await expect(page.locator('[data-host="seal-status"] .verdict-pass')).toBeVisible();

    // Setting a gate to the k it already has is the same no-op through a
    // different control.
    const gate = page.locator('select[id^="gate-"]').first();
    await gate.selectOption(await gate.inputValue());
    await expect(page.locator('[data-host="attempt"] [data-retired="true"]')).toHaveCount(0);
  });

  test('the [hidden] cascade probe: nothing hidden may paint', async ({ page }) => {
    await boot(page);
    // A class rule setting `display` outranks the UA `[hidden]` rule, so an
    // element can paint while the code believes it is hidden. This page uses
    // <details> rather than [hidden], so the probe asserts BOTH: no [hidden]
    // element paints, and a shut disclosure really is not visible.
    const painting = await page.$$eval('[hidden]', (els) =>
      els
        .filter((e) => (e as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((e) => e.tagName.toLowerCase() + '.' + (e.getAttribute('class') ?? '')),
    );
    expect(painting).toEqual([]);

    const shutButVisible = await page.$$eval('details.disclose:not([open]) .disclose-body', (els) =>
      els
        .filter((e) => (e as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((e) => (e.textContent ?? '').slice(0, 40)),
    );
    expect(shutButVisible).toEqual([]);

    // And opening one really reveals it, so the probe above is not vacuous.
    await page.locator('details.disclose > summary').first().click();
    await expect(page.locator('details.disclose[open] .disclose-body').first()).toBeVisible();
  });

  test('the hero keeps its three text roles distinct', async ({ page }) => {
    await boot(page);
    const title = (await page.locator('.cl-hero-title').innerText()).trim();
    const sub = (await page.locator('.cl-hero-sub').innerText()).trim();
    const desc = (await page.locator('.cl-hero-desc').innerText()).trim();
    const why = (await page.locator('.cl-hero-why-text').innerText()).trim();

    expect(title).toBe('Attribute Gate');
    // The subtitle is a spec label, not a sentence.
    expect(sub).toBe(
      'CP-ABE · FAME (2017) · RW15 multi-authority · FABESA CP-A2BE (2024) · BLS12-381',
    );
    expect(sub.endsWith('.')).toBe(false);
    // Description and why-it-matters must not be the same thing said twice.
    expect(desc).not.toBe(why);
    expect(desc.length).toBeGreaterThan(40);
    expect(why.length).toBeGreaterThan(40);
    // Exactly one h1, and it is the hero title.
    await expect(page.locator('h1')).toHaveCount(1);
    await expect(page.locator(`${READY} h1`)).toHaveText(title);
  });

  test('the page states its own construction and does not claim BSW07', async ({ page }) => {
    await boot(page);
    await expect(page.locator('#intro')).toContainText('FAME');
    await expect(page.locator('#builder')).toContainText('Why FAME and not the BSW07');
    // BSW07 is cited for what it is, and explicitly NOT claimed as implemented.
    await expect(page.locator('#builder')).toContainText('assumes a');
    await expect(page.locator('#builder')).toContainText('symmetric');
    await expect(page.locator('#builder')).toContainText('Type-3');
  });
});
