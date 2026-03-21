import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

export default defineConfig({
  testDir: './e2e',
  testIgnore: ['**/fixtures/**', '**/setup-test-user.ts'],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : Math.max(1, (require('os').cpus().length || 4) - 2),
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 30000,

  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    // Setup: login once, save session
    {
      name: 'setup',
      testMatch: /global-setup\.ts/,
    },
    // Auth tests: need fresh contexts (no saved session)
    {
      name: 'auth',
      testMatch: /auth\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // Everything else: parallel with shared session
    {
      name: 'chromium',
      testIgnore: /auth\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
});
