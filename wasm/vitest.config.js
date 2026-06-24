import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

export default defineConfig({
  optimizeDeps: {
    // Node-only packages pulled in transitively by the playwright provider.
    // They must not be pre-bundled for the browser test environment.
    exclude: ['playwright', 'playwright-core', 'fsevents', 'chromium-bidi'],
  },
  test: {
    include: ['tests/**/*.test.js'],
    setupFiles: ['./tests/setup.js'],
    testTimeout: 10000,
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
      headless: true,
    },
  },
});
