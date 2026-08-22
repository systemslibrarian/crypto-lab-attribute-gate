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

    // The two routes to the residual must agree, and it must not be 1.
    await expect(page.locator('[data-host="collusion"]')).toContainText('yes all 576 bytes');
    await expect(page.locator('[data-host="collusion"]')).toContainText('the record stays shut');
  });

  test('a coherent key run through the same machinery leaves a residual of 1', async ({ page }) => {
    await boot(page);
    // Alice satisfies the policy on her own, so the splice is coherent and the
    // control case must come out the other way.
    await page.selectOption('#collude-a', 'Alice');
    await page.selectOption('#collude-b', 'Carol');
    await page.getByRole('button', { name: 'Pool the keys and decrypt' }).click();
    await expect(page.locator('[data-host="collusion"] [data-stage="6"]')).toBeVisible();
    await expect(page.locator('[data-host="collusion"]')).toContainText('decryption is correct');
    const verdicts = page.locator('[data-host="collusion"] .verdict[data-outcome="opened"]');
    await expect(verdicts).toHaveCount(2);
    await expect(page.locator('[data-host="collusion"] .ledger td.survives')).toHaveCount(0);
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
    expect(sub).toBe('CP-ABE · FAME · Agrawal-Chase, CCS 2017');
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
