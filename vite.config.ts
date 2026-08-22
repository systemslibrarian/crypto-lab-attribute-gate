import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-attribute-gate/
export default defineConfig({
  base: '/crypto-lab-attribute-gate/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // A single round-trip here is a Setup, a KeyGen and an Encrypt over
    // BLS12-381, and the end-to-end cases run several against a policy zoo --
    // tens of pairings and hundreds of G1 exponentiations per test. Vitest's
    // 5s default fails those on any loaded machine, which is a stopwatch
    // result rather than a correctness one. No assertion is relaxed by this;
    // only the wall clock is.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
