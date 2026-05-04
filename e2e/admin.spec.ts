import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { psql, fetchMailpitMessages, clearMailpit } from './fixtures/helpers';

// storageState: 'e2e/.auth/admin.json' is set by the 'admin' project in playwright.config.ts

function detectAdminEmail(): string {
  try {
    const containerName = execSync(
      'docker ps --format "{{.Names}}" | grep -E "schautrack.*web"',
      { encoding: 'utf-8' }
    ).trim().split('\n')[0];
    if (containerName) {
      const email = execSync(
        `docker exec ${containerName} printenv ADMIN_EMAIL`,
        { encoding: 'utf-8' }
      ).trim();
      if (email) return email;
    }
  } catch { /* ignore */ }
  return 'admin@test.com';
}

const ADMIN_EMAIL = detectAdminEmail();

test.describe('Admin Panel', () => {
  test.describe.configure({ mode: 'serial' });
  test('admin panel loads', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });

    // The admin page shows Application Settings and a user list
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 5000 });
  });

  test('non-admin is redirected away from admin panel', async ({ browser }) => {
    // Use main test user session (non-admin)
    const context = await browser.newContext({ storageState: 'e2e/.auth/user.json' });
    const page = await context.newPage();

    await page.goto('/admin');
    // useRequireAdmin redirects non-admins to /dashboard
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });

    await context.close();
  });

  test('unauthenticated user is redirected to login from admin panel', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/admin');
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });

    await context.close();
  });

  test('toggle registration mode and verify it persists', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    const regSelect = page.getByLabel('ENABLE_REGISTRATION');
    await regSelect.scrollIntoViewIfNeeded();
    await expect(regSelect).toBeVisible({ timeout: 5000 });

    // Skip if env-controlled (disabled)
    if (await regSelect.isDisabled()) {
      test.skip();
      return;
    }

    const current = await regSelect.inputValue();
    const flipped = current === 'true' ? 'false' : 'true';

    await regSelect.selectOption(flipped);

    // Save
    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(800);

    // Reload and verify the value persisted
    await page.reload();
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    const reloadedSelect = page.getByLabel('ENABLE_REGISTRATION');
    await reloadedSelect.scrollIntoViewIfNeeded();
    await expect(reloadedSelect).toHaveValue(flipped, { timeout: 5000 });

    // Restore
    await reloadedSelect.selectOption(current);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(500);
  });

  test('create invite code', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Invite Codes')).toBeVisible({ timeout: 10000 });

    // Click Create Invite (without filling email — email is optional)
    await page.getByRole('button', { name: 'Create Invite' }).click();

    // An invite code (monospace code text) should appear in the list
    await expect(page.locator('code').first()).toBeVisible({ timeout: 5000 });
  });

  test('delete unused invite code', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Invite Codes')).toBeVisible({ timeout: 10000 });

    // Create a fresh invite to ensure we have one to delete
    await page.getByRole('button', { name: 'Create Invite' }).click();
    await page.waitForTimeout(1000);

    // Count invites by their <code> elements in the invite list section
    const inviteSection = page.getByText('Invite Codes').locator('..').locator('..');
    const codesBefore = await inviteSection.locator('code').count();
    expect(codesBefore).toBeGreaterThan(0);

    // Find and click the first Delete button in the invite section
    const inviteDeleteBtn = inviteSection.locator('button').filter({ hasText: /^Delete$/ }).first();
    await inviteDeleteBtn.scrollIntoViewIfNeeded();
    await inviteDeleteBtn.click();

    // Code count should decrease by 1
    await expect(inviteSection.locator('code')).toHaveCount(codesBefore - 1, { timeout: 5000 });
  });

  test('view user list with test users', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });

    // List uses infinite scroll (25 visible initially). Use the search to
    // find the test user instead of relying on it being in the first batch.
    await page.getByPlaceholder('Search by email...').fill('test@test.com');
    await expect(page.getByText('test@test.com').first()).toBeVisible({ timeout: 5000 });
  });

  test('admin cannot delete their own account via API', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });

    // Get admin's own user ID
    const meRes = await page.request.get('/api/me');
    const { user } = await meRes.json();

    // Get CSRF token
    const csrfRes = await page.request.get('/api/csrf');
    const { token } = await csrfRes.json();

    // Try to delete self via API — should return 400
    const deleteRes = await page.request.post(`/admin/users/${user.id}/delete`, {
      headers: { 'X-CSRF-Token': token },
    });
    expect(deleteRes.status()).toBe(400);
    const body = await deleteRes.json();
    expect(body.error).toContain('Cannot delete yourself');
  });

  test('toggle barcode feature and verify it persists', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // The form has proper htmlFor/id pairing so getByLabel resolves directly
    // to the input/select.
    const barcodeSelect = page.getByLabel('ENABLE_BARCODE');
    await barcodeSelect.scrollIntoViewIfNeeded();
    await expect(barcodeSelect).toBeVisible({ timeout: 5000 });

    const current = await barcodeSelect.inputValue();
    const flipped = current === 'true' ? 'false' : 'true';

    await barcodeSelect.selectOption(flipped);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(800);

    // Reload and verify persisted
    await page.reload();
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    const barcodeSelect2 = page.getByLabel('ENABLE_BARCODE');
    await barcodeSelect2.scrollIntoViewIfNeeded();
    await expect(barcodeSelect2).toHaveValue(flipped, { timeout: 5000 });

    // Restore
    await barcodeSelect2.selectOption(current);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(500);
  });

  test('configure legal settings and verify they persist', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // Use a DB-only (non-env-controlled) setting like AI_ENDPOINT to test save/persist.
    // SUPPORT_EMAIL, IMPRINT_ADDRESS, IMPRINT_EMAIL may be env-controlled (disabled).
    const endpointInput = page.getByLabel('AI_ENDPOINT');
    await endpointInput.scrollIntoViewIfNeeded();

    // Skip if env-controlled
    if (await endpointInput.isDisabled()) {
      test.skip();
      return;
    }

    const original = await endpointInput.inputValue();
    const testValue = 'https://test-endpoint.example.com/v1';

    await endpointInput.click({ clickCount: 3 });
    await endpointInput.fill(testValue);

    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(800);

    // Reload and verify
    await page.reload();
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    const endpointInput2 = page.getByLabel('AI_ENDPOINT');
    await endpointInput2.scrollIntoViewIfNeeded();
    await expect(endpointInput2).toHaveValue(testValue, { timeout: 5000 });

    // Restore original value
    await endpointInput2.click({ clickCount: 3 });
    await endpointInput2.fill(original);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(500);
  });

  test('delete a user with cascade and verify removal', async ({ page }) => {
    const deleteEmail = 'admin-delete-test@test.com';

    // Create a dummy user with some entries via psql
    const hash = psql(`SELECT password_hash FROM users WHERE email = 'test@test.com' LIMIT 1`);
    psql(`DELETE FROM users WHERE email = '${deleteEmail}'`);
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${deleteEmail}', '${hash}', true)`);
    const userId = psql(`SELECT id FROM users WHERE email = '${deleteEmail}'`);
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES (${userId}, CURRENT_DATE, 500, 'Test entry')`);

    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });

    // Search for the user
    const searchInput = page.locator('input[placeholder="Search by email..."]');
    await searchInput.fill(deleteEmail);
    await page.waitForTimeout(500); // debounce
    await expect(page.getByText(deleteEmail).first()).toBeVisible({ timeout: 5000 });

    // Handle the confirm dialog BEFORE clicking
    page.once('dialog', (dialog) => dialog.accept());

    // Click the Delete button — find it near the email text
    const deleteBtn = page.locator('button').filter({ hasText: 'Delete' }).last();
    await deleteBtn.click();

    // Wait for removal — clear search to see full list
    await searchInput.clear();
    await page.waitForTimeout(500);
    await expect(page.getByText(deleteEmail)).not.toBeVisible({ timeout: 5000 });

    // Verify via psql the user is gone
    const gone = psql(`SELECT id FROM users WHERE email = '${deleteEmail}'`);
    expect(gone).toBe('');
  });

  test('invite email sent via MailPit', async ({ page }) => {
    const inviteEmail = 'invite-check@test.com';
    await clearMailpit();

    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Invite Codes')).toBeVisible({ timeout: 10000 });

    // Fill in the email and create invite
    const emailInput = page.locator('input[placeholder="Email (optional)"]');
    await emailInput.fill(inviteEmail);
    await page.getByRole('button', { name: 'Create Invite' }).click();

    // Wait for invite to appear
    await expect(page.locator('code').first()).toBeVisible({ timeout: 5000 });

    // Verify email was sent to MailPit
    let messages: Awaited<ReturnType<typeof fetchMailpitMessages>> = [];
    for (let i = 0; i < 10; i++) {
      messages = await fetchMailpitMessages(inviteEmail);
      if (messages.length > 0) break;
      await page.waitForTimeout(500);
    }
    expect(messages.length).toBeGreaterThan(0);
    expect(messages[0].To.some((t) => t.Address === inviteEmail)).toBe(true);
  });

  test('cannot delete already-used invite code', async ({ page }) => {
    // Create an invite via psql that is already used
    const adminId = psql(`SELECT id FROM users WHERE email = '${ADMIN_EMAIL}'`);
    psql(`DELETE FROM invite_codes WHERE email = 'used-invite@test.com'`);
    // Insert a used invite: used_by points to an existing user
    const testUserId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    psql(
      `INSERT INTO invite_codes (code, email, created_by, used_by, used_at) ` +
      `VALUES ('USED-INVITE-CODE-E2E', 'used-invite@test.com', ${adminId}, ${testUserId}, NOW())`
    );

    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Invite Codes')).toBeVisible({ timeout: 10000 });

    // Find the invite row by code text, then go up to the row container
    const codeEl = page.locator('code').filter({ hasText: 'USED-INVITE-CODE-E2E' });
    await expect(codeEl).toBeVisible({ timeout: 5000 });
    const inviteRow = codeEl.locator('../..'); // code -> flex-1 div -> row div

    // There should be no Delete button for a used invite
    const deleteBtn = inviteRow.locator('button').filter({ hasText: 'Delete' });
    await expect(deleteBtn).not.toBeVisible({ timeout: 2000 });

    // Cleanup
    psql(`DELETE FROM invite_codes WHERE code = 'USED-INVITE-CODE-E2E'`);
  });

  test('env-var controlled settings are locked and cannot be saved', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // IMPRINT_ADDRESS, IMPRINT_EMAIL, SUPPORT_EMAIL are set via env vars
    // Their inputs should be disabled
    const imprintInput = page.getByLabel('IMPRINT_ADDRESS');
    await imprintInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(imprintInput).toBeDisabled({ timeout: 5000 });

    const supportInput = page.getByLabel('SUPPORT_EMAIL');
    await expect(supportInput).toBeDisabled({ timeout: 5000 });

    // Also verify via API: try to POST a change to an env-controlled setting
    const csrfRes = await page.request.get('/api/csrf');
    const { token: csrfToken } = await csrfRes.json();

    const saveRes = await page.request.post('/admin/settings', {
      data: { settings: { support_email: 'test@example.com' } },
      headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json' },
    });
    // Backend rejects changes to env-controlled settings (400 or 403)
    expect([400, 403]).toContain(saveRes.status());
  });

  test('invite list shows statuses for unused, used, and expired invites', async ({ page }) => {
    const adminId = psql(`SELECT id FROM users WHERE email = '${ADMIN_EMAIL}'`);
    const testUserId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);

    // Remove any leftover test invites
    psql(`DELETE FROM invite_codes WHERE code IN ('E2E-UNUSED-CODE', 'E2E-USED-CODE', 'E2E-EXPIRED-CODE')`);

    // Unused invite (no expiry)
    psql(`INSERT INTO invite_codes (code, email, created_by) VALUES ('E2E-UNUSED-CODE', 'unused@test.com', ${adminId})`);

    // Used invite
    psql(
      `INSERT INTO invite_codes (code, email, created_by, used_by, used_at) ` +
      `VALUES ('E2E-USED-CODE', 'used2@test.com', ${adminId}, ${testUserId}, NOW())`
    );

    // Expired invite (expires_at in the past, not used)
    psql(
      `INSERT INTO invite_codes (code, email, created_by, expires_at) ` +
      `VALUES ('E2E-EXPIRED-CODE', 'expired@test.com', ${adminId}, NOW() - INTERVAL '1 day')`
    );

    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Invite Codes')).toBeVisible({ timeout: 10000 });

    // Helper to find an invite row by its code
    function inviteRow(code: string) {
      return page.locator('code').filter({ hasText: code }).locator('../..');
    }

    // Unused invite: should show a Delete button
    const unusedRow = inviteRow('E2E-UNUSED-CODE');
    await expect(unusedRow).toBeVisible({ timeout: 5000 });
    await expect(unusedRow.locator('button').filter({ hasText: 'Delete' })).toBeVisible({ timeout: 3000 });

    // Used invite: should NOT have Delete button
    const usedRow = inviteRow('E2E-USED-CODE');
    await expect(usedRow).toBeVisible({ timeout: 5000 });
    await expect(usedRow.locator('button').filter({ hasText: 'Delete' })).not.toBeVisible({ timeout: 2000 });

    // Expired invite: should be visible
    const expiredRow = inviteRow('E2E-EXPIRED-CODE');
    await expiredRow.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(expiredRow).toBeVisible({ timeout: 5000 });
    await expect(expiredRow.getByText(/expires/i)).toBeVisible({ timeout: 3000 });

    // Cleanup
    psql(`DELETE FROM invite_codes WHERE code IN ('E2E-UNUSED-CODE', 'E2E-USED-CODE', 'E2E-EXPIRED-CODE')`);
  });

  test('settings sections render with the right keys', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // Spot-check each section title — confirms canonical sections render.
    // exact:true so 'Features' doesn't also match 'AI Features'.
    for (const title of ['General', 'AI Features', 'OIDC / SSO', 'Passkeys', 'Features', 'SMTP', 'Security', 'Legal Pages', 'SEO / Deployment']) {
      await expect(page.getByRole('heading', { name: title, level: 3, exact: true })).toBeVisible({ timeout: 3000 });
    }

    // Spot-check that the new keys exist as labelled fields.
    for (const key of ['STEP_UP_TTL', 'OIDC_ISSUER', 'PASSKEYS_RP_NAME', 'SMTP_HOST', 'BASE_URL']) {
      await expect(page.getByLabel(key)).toBeVisible({ timeout: 3000 });
    }
  });

  test('validators reject bad values via API', async ({ request }) => {
    const csrfRes = await request.get('/api/csrf');
    const setCookie = csrfRes.headers()['set-cookie'] || '';
    const { token: csrfToken } = await csrfRes.json();

    // Server-validated cases — each should be rejected with 400.
    const cases = [
      { settings: { step_up_ttl: 'not-a-duration' } },
      { settings: { smtp_port: '99999' } },
      { settings: { rate_limit_auth: '-5' } },
      { settings: { passkeys_rp_id: 'https://schautrack.com' } }, // scheme not allowed
      { settings: { oidc_issuer: 'not a url' } },
    ];
    for (const body of cases) {
      const res = await request.post('/admin/settings', {
        data: body,
        headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json', Cookie: setCookie },
      });
      expect(res.status(), `expected 400 for ${JSON.stringify(body)}`).toBe(400);
    }
  });

  test('secret values are not returned by the API', async ({ request }) => {
    // Seed a known-shape secret so we can prove it isn't echoed back.
    psql(`INSERT INTO admin_settings (key, value) VALUES ('ai_key', 'sk-test-secret-MUST-NOT-LEAK') ON CONFLICT (key) DO UPDATE SET value = 'sk-test-secret-MUST-NOT-LEAK'`);
    try {
      const res = await request.get('/api/admin');
      const body = await res.json();
      const ai = body.settings.ai_key;
      expect(ai).toBeTruthy();
      expect(ai.secret).toBe(true);
      // value field is masked, isSet flag tells the UI something is stored.
      expect(ai.value).toBe('');
      expect(ai.isSet).toBe(true);
    } finally {
      psql(`DELETE FROM admin_settings WHERE key = 'ai_key'`);
    }
  });

  test('admin save writes an audit_log row', async ({ request }) => {
    const adminId = psql(`SELECT id FROM users WHERE email = '${ADMIN_EMAIL}'`);
    psql(`DELETE FROM audit_log WHERE action = 'admin_setting_changed' AND user_id = ${adminId} AND metadata->>'key' = 'ai_endpoint'`);

    const csrfRes = await request.get('/api/csrf');
    const setCookie = csrfRes.headers()['set-cookie'] || '';
    const { token: csrfToken } = await csrfRes.json();

    const newEndpoint = `https://audit-test-${Date.now()}.example.com/v1`;
    const res = await request.post('/admin/settings', {
      data: { settings: { ai_endpoint: newEndpoint } },
      headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json', Cookie: setCookie },
    });
    expect(res.status()).toBe(200);

    // Audit row must exist with the action + key in metadata.
    const found = psql(
      `SELECT count(*) FROM audit_log WHERE action = 'admin_setting_changed' AND user_id = ${adminId} AND metadata->>'key' = 'ai_endpoint' AND metadata->>'value' = '${newEndpoint}'`,
    );
    expect(found).toBe('1');

    // Cleanup
    psql(`DELETE FROM admin_settings WHERE key = 'ai_endpoint'`);
  });
});
