import { test as base, expect, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const AUTH_FILE = path.join(__dirname, '..', '.auth', 'user.json');

/**
 * Log in as the test user. Reuses cached session when possible.
 */
export async function login(page: Page) {
  // Try cached session first
  if (fs.existsSync(AUTH_FILE)) {
    try {
      const state = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8'));
      if (state.cookies?.length > 0) {
        await page.context().addCookies(state.cookies);
        await page.goto('/dashboard');
        // Verify we're on dashboard (not redirected to login)
        await page.waitForURL('/dashboard', { timeout: 5000 });
        return;
      }
    } catch {
      // Session expired or invalid — delete and do fresh login
      try { fs.unlinkSync(AUTH_FILE); } catch {}
    }
  }

  // Fresh login
  await page.goto('/login');
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();
  await page.waitForURL('/dashboard', { timeout: 15000 });

  // Save session
  const dir = path.dirname(AUTH_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  await page.context().storageState({ path: AUTH_FILE });
}

export { base as test, expect };
