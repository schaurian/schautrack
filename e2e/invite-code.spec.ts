import { test, expect, Browser } from '@playwright/test';
import { psql } from './fixtures/helpers';

const ADMIN_STORAGE = 'e2e/.auth/admin.json';

/**
 * Make an authenticated API request using the admin session.
 * Fetches a fresh CSRF token and includes it in the request headers.
 */
async function adminApiRequest(
  browser: Browser,
  method: string,
  path: string,
  body?: Record<string, unknown>
): Promise<{ status: number; data: unknown }> {
  const context = await browser.newContext({ storageState: ADMIN_STORAGE });

  try {
    const csrfRes = await context.request.get('/api/csrf');
    const { token } = await csrfRes.json();

    const res = await context.request.fetch(path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'Accept': 'application/json',
      },
      data: body ? JSON.stringify(body) : undefined,
    });

    const data = await res.json().catch(() => ({}));
    return { status: res.status(), data };
  } finally {
    await context.close();
  }
}

test.describe('Invite-Only Registration', () => {
  test.describe.configure({ mode: 'serial' });

  // Track invite codes created during tests for cleanup
  const createdInviteCodes: string[] = [];

  test.afterAll(async ({ browser }) => {
    // Restore registration to open mode via API (so the in-memory cache is invalidated)
    await adminApiRequest(browser, 'POST', '/admin/settings', {
      settings: { enable_registration: 'true' },
    });

    // Clean up any invite codes created during tests
    for (const code of createdInviteCodes) {
      psql(`DELETE FROM invite_codes WHERE code = '${code}'`);
    }

    // Clean up any test users registered during these tests
    psql(`DELETE FROM users WHERE email LIKE 'invite-reg-%@test.com'`);
  });

  test('invite code field is shown when registration is invite-only', async ({ browser }) => {
    // Enable invite-only mode
    const res = await adminApiRequest(browser, 'POST', '/admin/settings', {
      settings: { enable_registration: 'false' },
    });
    expect(res.status).toBe(200);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    // The invite code field should be visible when registration requires invite
    await expect(page.getByLabel('Invite Code')).toBeVisible({ timeout: 10000 });

    await context.close();
  });

  test('valid invite code allows registration', async ({ browser }) => {
    // Create an invite code
    const inviteRes = await adminApiRequest(browser, 'POST', '/admin/invites', {});
    expect((inviteRes.data as { ok: boolean }).ok).toBe(true);
    const code = (inviteRes.data as { invite: { code: string } }).invite.code;
    createdInviteCodes.push(code);

    const registrationEmail = `invite-reg-${Date.now()}@test.com`;
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    // Fill in credentials + invite code
    await page.getByLabel('Email').fill(registrationEmail);
    await page.getByLabel('Password').fill('invitepass1234');
    await page.getByLabel('Confirm Password').fill('invitepass1234');
    await expect(page.getByLabel('Invite Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Invite Code').fill(code);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Step 2: captcha
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Create Account' }).click();

    // Should succeed — redirect to verify-email or dashboard
    await page.waitForURL(/\/verify-email|\/dashboard/, { timeout: 15000 });
    const url = page.url();
    expect(url).toMatch(/\/(verify-email|dashboard)/);

    await context.close();
  });

  test('invalid invite code shows error', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    await page.getByLabel('Email').fill(`invite-bad-${Date.now()}@test.com`);
    await page.getByLabel('Password').fill('invitepass1234');
    await page.getByLabel('Confirm Password').fill('invitepass1234');
    await expect(page.getByLabel('Invite Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Invite Code').fill('INVALID-CODE-XXXXXX');
    await page.getByRole('button', { name: 'Continue' }).click();

    // Captcha step
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Create Account' }).click();

    // Should show an error about the invalid invite code
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/invalid invite code/i)).toBeVisible({ timeout: 5000 });

    // Should stay on register page
    await expect(page).toHaveURL(/\/register/);

    await context.close();
  });

  test('expired invite code shows error', async ({ browser }) => {
    // Insert an already-expired invite code directly into the DB
    const expiredCode = `EXPIRED-${Date.now()}`;
    psql(`
      INSERT INTO invite_codes (code, created_by, expires_at)
      VALUES ('${expiredCode}', (SELECT id FROM users WHERE email = 'admin@test.com'), NOW() - INTERVAL '1 day')
    `);
    createdInviteCodes.push(expiredCode);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    await page.getByLabel('Email').fill(`invite-expired-${Date.now()}@test.com`);
    await page.getByLabel('Password').fill('invitepass1234');
    await page.getByLabel('Confirm Password').fill('invitepass1234');
    await expect(page.getByLabel('Invite Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Invite Code').fill(expiredCode);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Captcha step
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Create Account' }).click();

    // Should show an error about the expired code
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/expired/i)).toBeVisible({ timeout: 5000 });

    await expect(page).toHaveURL(/\/register/);

    await context.close();
  });

  test('already-used invite code shows error', async ({ browser }) => {
    // Insert an invite code that is already marked as used
    const usedCode = `USED-${Date.now()}`;
    const adminId = psql(`SELECT id FROM users WHERE email = 'admin@test.com'`);
    psql(`
      INSERT INTO invite_codes (code, created_by, used_by, used_at, expires_at)
      VALUES ('${usedCode}', ${adminId}, ${adminId}, NOW(), NOW() + INTERVAL '14 days')
    `);
    createdInviteCodes.push(usedCode);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    await page.getByLabel('Email').fill(`invite-used-${Date.now()}@test.com`);
    await page.getByLabel('Password').fill('invitepass1234');
    await page.getByLabel('Confirm Password').fill('invitepass1234');
    await expect(page.getByLabel('Invite Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Invite Code').fill(usedCode);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Captcha step
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Create Account' }).click();

    // Should show an error about the already-used code
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/already been used/i)).toBeVisible({ timeout: 5000 });

    await expect(page).toHaveURL(/\/register/);

    await context.close();
  });

  test('open registration: invite code field is not shown', async ({ browser }) => {
    // Restore open registration via API (invalidates the in-memory settings cache)
    await adminApiRequest(browser, 'POST', '/admin/settings', {
      settings: { enable_registration: 'true' },
    });

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    // Invite code field should NOT be visible in open registration mode
    await expect(page.getByLabel('Invite Code')).not.toBeVisible({ timeout: 5000 });

    await context.close();
  });
});
