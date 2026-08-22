import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-attribute-gate/
export default defineConfig({
  base: '/crypto-lab-attribute-gate/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
