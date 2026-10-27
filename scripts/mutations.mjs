// Clean-baseline mutation gate for Attribute Gate.
//
// The README's "Proving the gates bite" table has documented nine hand-applied
// mutations since the A-D-03/L-R-03 deliveries; until this file existed nothing
// could replay them, so a regression in any owning test would have gone
// unnoticed. This runner is the fleet pattern (Attestation Gate, Matsui Line,
// Residue Gate, Shelf Oracle): for every recipe it proves, in order,
//
//   1. the unmodified copy passes the WHOLE unit suite and builds,
//   2. the named owning test is green on the unmodified copy,
//   3. the patch produces a NON-EMPTY source change and the production bundle
//      hash moves (a mutation the build never picked up proves nothing),
//   4. the named owning test goes RED on a test failure -- a timeout, a crash,
//      a missing module or a server that failed to start is NOT a kill,
//   5. the source is restored byte for byte, the bundle hash returns to the
//      baseline, and the owning test is green again.
//
// Eight recipes are owned by Vitest tests and one by the Playwright
// accessibility gate, which runs against a fresh production build served by
// `vite preview` (CI=1 makes the Playwright config rebuild and refuse to reuse
// a running server).
//
// Run from the repository root: node scripts/mutations.mjs [mutation name]

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { stripVTControlCharacters } from 'node:util';

const unit = (spec, test) => ({ runner: 'vitest', spec, test });
const browser = (project, spec, test) => ({ runner: 'playwright', project, spec, test });

const mutations = [
  {
    name: 'Decrypt returns den / num instead of num / den',
    file: 'src/fame/fame.ts',
    anchor: '  return { ok: true, recovered: gtDiv(num, den), reconstruction: rec, num, den };',
    replacement: '  return { ok: true, recovered: gtDiv(den, num), reconstruction: rec, num, den };',
    ...unit('src/fame/fame.test.ts', 'msk is not a decryption key; it mints one, and then that key decrypts'),
  },
  {
    name: 'indexedLabel collapses every copy to :1 (the reference implementation\'s index-stripping bug)',
    file: 'src/fame/oneuse.ts',
    anchor: '  return `${name}:${copy}`;',
    replacement: '  return `${name}:${copy * 0 + 1}`;',
    ...unit('src/fame/msp.test.ts', 'makes pi injective, which is what FAME requires'),
  },
  {
    name: 'the Lagrange numerator loses its sign',
    file: 'src/fame/msp.ts',
    anchor: '      acc = mulMod(acc, divMod(mod(-xj), mod(xi - xj)));',
    replacement: '      acc = mulMod(acc, divMod(mod(xj), mod(xi - xj)));',
    ...unit('src/fame/msp.test.ts', 'the basis sums to 1 at zero for any point set'),
  },
  {
    name: '--border-strong degraded to the decorative --border token',
    file: 'src/style.css',
    anchor: '  --border-strong: #5c7181;',
    replacement: '  --border-strong: var(--border);',
    ...browser('a11y', 'e2e/a11y.spec.ts', 'no WCAG A/AA violations at desktop width'),
  },
  {
    name: 'FABESA ct1 raises both hidden-value hashes by s1, discarding s2 from the second branch',
    file: 'src/fabesa/fabesa.ts',
    anchor: '      g1Pow(hashHiddenAttribute(1, row), s2),',
    replacement: '      g1Pow(hashHiddenAttribute(1, row), s1),',
    ...unit('src/fabesa/fabesa.test.ts', 'Encrypt exponentiates both hash terms and uses g3 for the MSP share'),
  },
  {
    name: 'the hard FABESA candidate ceiling moves from 32 to 33',
    file: 'src/fabesa/fabesa.ts',
    anchor: 'export const MAX_RECONSTRUCTION_CANDIDATES = 32;',
    replacement: 'export const MAX_RECONSTRUCTION_CANDIDATES = 33;',
    ...unit('src/fabesa/fabesa.test.ts', 'fails closed when the matched-row or candidate bound is exceeded'),
  },
  {
    name: 'RW15\'s GID random oracle hashes one constant identifier for every user',
    file: 'src/rw15/rw15.ts',
    anchor: '  const point = bls.G2.hashToCurve(rwGidHashInput(canonical), {',
    replacement: "  const point = bls.G2.hashToCurve(rwGidHashInput('gid'), {",
    ...unit('src/rw15/rw15.test.ts', 'blocks the strongest raw cross-GID pooling attempt, not merely a metadata mismatch'),
  },
  {
    name: 'the epoch gate changes from business AND epoch to business OR epoch',
    file: 'src/revocation/epoch.ts',
    anchor: '    id: `revocation/root/${epoch}`,\n    threshold: 2,',
    replacement: '    id: `revocation/root/${epoch}`,\n    threshold: 1,',
    ...unit('src/revocation/epoch.test.ts', 'withholds a complete new key and rejects the revoked holder on new data'),
  },
  {
    name: 'the trusted-checkpoint comparison accepts every well-shaped checkpoint',
    file: 'src/revocation/epoch.ts',
    anchor:
      '    checkpoint.revision === header.revision &&\n    bytesEqual(checkpoint.headerDigest, computeAccessHeaderDigest(header))',
    replacement: '    checkpoint.revision >= 1 &&\n    isBytes(checkpoint.headerDigest)',
    ...unit('src/revocation/epoch.test.ts', 'refuses a stale source checkpoint and a same-epoch pseudo-update'),
  },
];

const INFRASTRUCTURE = /No test files found|Cannot find module|Failed to load url|Unhandled Error|error TS\d+|ERR_CONNECTION_REFUSED|webServer was not able|Timed out waiting \d+ms from config\.webServer|Error: Process from config\.webServer|Test timed out|Test timeout of/;

function run(command, args, timeout) {
  const child = spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout,
  });
  return {
    ok: child.status === 0 && !child.error && !child.signal,
    status: child.status,
    signal: child.signal,
    error: child.error,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
  };
}

function requirePass(result, label) {
  if (!result.ok) {
    throw new Error(`${label} failed (status ${result.status}, signal ${result.signal ?? 'none'}):\n${result.output.slice(-4000)}`);
  }
}

function build() {
  requirePass(run('npm', ['run', 'build'], 300_000), 'build');
}

/** Hash of every emitted asset, JavaScript AND CSS: one recipe mutates the stylesheet. */
function bundleHash() {
  const dir = 'dist/assets';
  const files = readdirSync(dir).filter((file) => statSync(join(dir, file)).isFile()).sort();
  if (files.length === 0) throw new Error('build produced no assets');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(dir, file)));
  return hash.digest('hex');
}

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function owningTest(mutation) {
  if (mutation.runner === 'vitest') {
    return run('npx', ['vitest', 'run', mutation.spec, '-t', escapeRegex(mutation.test)], 300_000);
  }
  // --retries=0 overrides the config's CI retry so a kill is one red run, and
  // CI=1 makes the webServer rebuild from the (mutated) source instead of
  // reusing a preview that is still serving the clean bundle.
  return run(
    'npx',
    ['playwright', 'test', mutation.spec, `--project=${mutation.project}`, '-g', escapeRegex(mutation.test), '--retries=0', '--reporter=line'],
    1_500_000
  );
}

function requireNamedGreen(result, mutation, label) {
  requirePass(result, label);
  const exactlyOne = mutation.runner === 'vitest' ? /Tests\s+1 passed\b/ : /\b1 passed\b/;
  if (!exactlyOne.test(result.output) || /\d+ failed\b/.test(result.output)) {
    throw new Error(`${label} did not execute exactly one passing test:\n${result.output.slice(-3000)}`);
  }
}

function requireNamedRed(result, mutation) {
  if (result.ok) throw new Error(`${mutation.name}: mutation SURVIVED its owning test`);
  if (INFRASTRUCTURE.test(result.output)) {
    throw new Error(`${mutation.name}: an infrastructure failure or timeout is not a kill:\n${result.output.slice(-3000)}`);
  }
  if (!result.output.includes(mutation.test)) {
    throw new Error(`${mutation.name}: the failure did not name its owning test:\n${result.output.slice(-3000)}`);
  }
  const red = mutation.runner === 'vitest' ? /Tests\s+1 failed\b/ : /\b1 failed\b/;
  if (!red.test(result.output)) {
    throw new Error(`${mutation.name}: the owning test did not fail exactly once:\n${result.output.slice(-3000)}`);
  }
}

const requested = process.argv[2];
const selected = requested ? mutations.filter((mutation) => mutation.name === requested) : mutations;
if (selected.length === 0) throw new Error(`unknown mutation: ${requested}`);

const files = [...new Set(selected.map((mutation) => mutation.file))];
if (run('git', ['diff', '--quiet', 'HEAD', '--', ...files], 60_000).status !== 0) {
  throw new Error('commit the mutated source files before replaying mutations; the harness restores from disk, not from git');
}

build();
const baseline = bundleHash();
// The WHOLE unit suite, not just the files these mutations touch.
requirePass(run('npx', ['vitest', 'run'], 900_000), 'unmutated unit baseline');
console.log('baseline: unmutated copy PASSES');

const evidence = [];
for (const [index, mutation] of selected.entries()) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: the anchor must occur exactly once in ${mutation.file}`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: named baseline`);
  let record;
  try {
    const changed = original.replace(mutation.anchor, mutation.replacement);
    if (changed === original) throw new Error(`${mutation.name}: the patch changed nothing`);
    writeFileSync(mutation.file, changed);
    const diff = run('git', ['diff', '--no-ext-diff', '--', mutation.file], 60_000);
    if (diff.output.trim() === '') throw new Error(`${mutation.name}: the source diff was empty`);
    build();
    const mutant = bundleHash();
    if (mutant === baseline) throw new Error(`${mutation.name}: the production bundle did not change`);
    const red = owningTest(mutation);
    requireNamedRed(red, mutation);
    record = {
      name: mutation.name,
      file: mutation.file,
      runner: mutation.runner,
      owningTest: mutation.test,
      baselineGreen: true,
      sourceDiffNonEmpty: true,
      baselineBundle: baseline,
      mutantBundle: mutant,
      bundleMoved: true,
      owningTestRed: true,
      failureExcerpt: red.output.split('\n').filter((line) => /expect|Error|✗|×|FAIL/.test(line)).slice(0, 6),
    };
    console.log(`caught ${index + 1}/${selected.length}: ${mutation.name} -> ${mutation.test}`);
  } finally {
    writeFileSync(mutation.file, original);
    if (readFileSync(mutation.file, 'utf8') !== original) {
      throw new Error(`${mutation.name}: source was not restored byte for byte`);
    }
    build();
    if (bundleHash() !== baseline) throw new Error(`${mutation.name}: restored bundle differs from the baseline`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: restored baseline`);
  record.restoredGreen = true;
  evidence.push(record);
  writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
}

requirePass(run('npx', ['vitest', 'run'], 900_000), 'restored unit baseline');
console.log(`all ${evidence.length} of ${selected.length} mutation(s) caught; sources and production bundle restored byte for byte`);
