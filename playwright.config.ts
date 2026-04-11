import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

export default defineConfig({
  testDir: './e2e',
  testIgnore: ['**/fixtures/**', '**/setup-test-user.ts'],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 1,
  workers: process.env.CI ? 2 : Math.min(4, require('os').cpus().length || 4),
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 60000,
  expect: { timeout: 10000 },

  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    // Setup: login as main test user, save session
    {
      name: 'setup',
      testMatch: /global-setup\.ts/,
    },
    // Admin setup: login as admin user, save session
    {
      name: 'admin-setup',
      testMatch: /admin-setup\.ts/,
      dependencies: ['setup'],
    },
    // Auth tests: need fresh contexts (no saved session)
    {
      name: 'auth',
      testMatch: /auth\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // 2FA tests: need fresh contexts and run serially
    {
      name: '2fa',
      testMatch: /two-factor\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // Admin tests: use admin session
    {
      name: 'admin',
      testMatch: /admin\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/admin.json',
      },
      dependencies: ['admin-setup'],
    },
    // Tests that modify admin_settings — run after admin+chromium to avoid interference
    {
      name: 'admin-settings',
      testMatch: [/barcode-extended\.spec\.ts/, /legal\.spec\.ts/, /invite-code\.spec\.ts/],
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['admin', 'chromium'],
    },
    // Everything else: parallel with shared session
    {
      name: 'chromium',
      testIgnore: [/auth\.spec\.ts/, /two-factor\.spec\.ts/, /admin\.spec\.ts/, /barcode-extended\.spec\.ts/, /legal\.spec\.ts/, /invite-code\.spec\.ts/],
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
});
