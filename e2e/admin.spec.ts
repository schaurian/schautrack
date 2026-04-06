import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { fetchMailpitMessages, clearMailpit } from './fixtures/helpers';

// storageState: 'e2e/.auth/admin.json' is set by the 'admin' project in playwright.config.ts

const ADMIN_EMAIL = 'admin@test.com';

const DB_CONTAINER = process.env.DB_CONTAINER || 'schautrack-test-db-1';
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';

function psql(sql: string): string {
  return execSync(
    `docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -tA`,
    { input: sql + '\n', encoding: 'utf-8' }
  ).trim();
}

test.describe('Admin Panel', () => {
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

    // Find the ENABLE_REGISTRATION select
    const regSelect = page.locator('select').filter({ has: page.locator('option[value="true"]') }).first();
    await regSelect.scrollIntoViewIfNeeded();
    await expect(regSelect).toBeVisible({ timeout: 5000 });

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

    const reloadedSelect = page.locator('select').filter({ has: page.locator('option[value="true"]') }).first();
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

    // Ensure at least one invite exists
    const hasInvites = await page.locator('code').count();
    if (hasInvites === 0) {
      await page.getByRole('button', { name: 'Create Invite' }).click();
      await expect(page.locator('code').first()).toBeVisible({ timeout: 5000 });
    }

    const codesBefore = await page.locator('code').count();

    // Click the Delete button for the first unused invite
    const deleteBtn = page.getByRole('button', { name: 'Delete' }).first();
    await deleteBtn.scrollIntoViewIfNeeded();
    // Note: the invite delete uses a plain <button> with text "Delete", not a Button component
    const inviteDeleteBtn = page.locator('button').filter({ hasText: /^Delete$/ }).first();
    await inviteDeleteBtn.click();

    // Code count should decrease by 1
    await expect(page.locator('code')).toHaveCount(codesBefore - 1, { timeout: 5000 });
  });

  test('view user list with test users', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });

    // The test user should appear in the user list
    await expect(page.getByText('test@test.com')).toBeVisible({ timeout: 5000 });
  });

  test('admin cannot delete their own account from the user list', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });

    // Find the row for the admin's own email
    const adminRow = page.locator('div').filter({ hasText: ADMIN_EMAIL }).filter({ has: page.locator('span:has-text("Verified")') }).first();
    await adminRow.scrollIntoViewIfNeeded({ timeout: 5000 });

    // The admin row should not have a Delete button (self-deletion is prevented server-side;
    // the backend returns 403 when trying to delete self). We verify the row exists but
    // clicking Delete should not remove the admin from the list.
    const deleteBtn = adminRow.locator('button', { hasText: 'Delete' });
    const hasSelfDelete = await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasSelfDelete) {
      // If a Delete button is present, clicking it should fail (server returns 403)
      // Intercept the response to check
      const [response] = await Promise.all([
        page.waitForResponse((res) => res.url().includes('/admin/users/') && res.url().includes('/delete')),
        deleteBtn.click(),
      ]);
      // Should be forbidden
      expect(response.status()).toBe(403);
      // Admin should still appear in the list
      await expect(page.getByText(ADMIN_EMAIL)).toBeVisible({ timeout: 3000 });
    } else {
      // No Delete button for self — this is the expected safe UI behavior
      await expect(deleteBtn).not.toBeVisible();
    }
  });

  test('toggle barcode feature and verify it persists', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // Find the ENABLE_BARCODE select — it has true/false options and its label reads 'ENABLE_BARCODE'
    const barcodeLabel = page.getByText('ENABLE_BARCODE');
    await barcodeLabel.scrollIntoViewIfNeeded();
    await expect(barcodeLabel).toBeVisible({ timeout: 5000 });

    // The select is the sibling element inside the same container
    const barcodeContainer = barcodeLabel.locator('..');
    const barcodeSelect = barcodeContainer.locator('select');
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

    const barcodeLabel2 = page.getByText('ENABLE_BARCODE');
    await barcodeLabel2.scrollIntoViewIfNeeded();
    const barcodeSelect2 = barcodeLabel2.locator('..').locator('select');
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

    // Update SUPPORT_EMAIL
    const supportEmailLabel = page.getByText('SUPPORT_EMAIL');
    await supportEmailLabel.scrollIntoViewIfNeeded();
    const supportEmailInput = supportEmailLabel.locator('..').locator('input');
    await supportEmailInput.click({ clickCount: 3 });
    await supportEmailInput.fill('legal-test@example.com');

    // Update IMPRINT_ADDRESS
    const imprintAddressLabel = page.getByText('IMPRINT_ADDRESS');
    const imprintAddressInput = imprintAddressLabel.locator('..').locator('input');
    await imprintAddressInput.click({ clickCount: 3 });
    await imprintAddressInput.fill('Test Corp\n123 Test St');

    // Update IMPRINT_EMAIL
    const imprintEmailLabel = page.getByText('IMPRINT_EMAIL');
    const imprintEmailInput = imprintEmailLabel.locator('..').locator('input');
    await imprintEmailInput.click({ clickCount: 3 });
    await imprintEmailInput.fill('imprint@example.com');

    await page.getByRole('button', { name: 'Save' }).click();
    await page.waitForTimeout(800);

    // Reload and verify
    await page.reload();
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    const supportEmailLabel2 = page.getByText('SUPPORT_EMAIL');
    await supportEmailLabel2.scrollIntoViewIfNeeded();
    const supportEmailInput2 = supportEmailLabel2.locator('..').locator('input');
    await expect(supportEmailInput2).toHaveValue('legal-test@example.com', { timeout: 5000 });

    const imprintEmailLabel2 = page.getByText('IMPRINT_EMAIL');
    const imprintEmailInput2 = imprintEmailLabel2.locator('..').locator('input');
    await expect(imprintEmailInput2).toHaveValue('imprint@example.com', { timeout: 5000 });
  });

  test('delete a user with cascade and verify removal', async ({ page }) => {
    const deleteEmail = 'admin-delete-test@test.com';

    // Create a dummy user with some entries via psql
    const hash = psql(`SELECT password_hash FROM users WHERE email = 'test@test.com' LIMIT 1`);
    psql(`DELETE FROM users WHERE email = '${deleteEmail}'`);
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${deleteEmail}', '${hash}', true)`);
    const userId = psql(`SELECT id FROM users WHERE email = '${deleteEmail}'`);
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, name) VALUES (${userId}, CURRENT_DATE, 500, 'Test entry')`);

    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });

    // Search for the user so they appear in the list
    const searchInput = page.locator('input[placeholder="Search by email..."]');
    await searchInput.fill(deleteEmail);
    await expect(page.getByText(deleteEmail)).toBeVisible({ timeout: 5000 });

    // Click the Delete button for this user row
    const userRow = page.locator('div').filter({ hasText: deleteEmail }).filter({ has: page.locator('button', { hasText: 'Delete' }) }).first();
    const deleteBtn = userRow.locator('button', { hasText: 'Delete' });
    await deleteBtn.scrollIntoViewIfNeeded();

    // Handle the confirm dialog
    page.on('dialog', (dialog) => dialog.accept());
    await deleteBtn.click();

    // The user should no longer appear in the list
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

    // Find the row for the used invite
    const usedRow = page.locator('div').filter({ hasText: 'USED-INVITE-CODE-E2E' }).first();
    await usedRow.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(usedRow).toBeVisible({ timeout: 5000 });

    // There should be no Delete button for a used invite — the UI shows "Used by ..." instead
    const deleteBtn = usedRow.locator('button', { hasText: 'Delete' });
    await expect(deleteBtn).not.toBeVisible({ timeout: 2000 });

    // Should show "Used by" indicator instead
    await expect(usedRow.getByText(/Used by/i)).toBeVisible({ timeout: 3000 });

    // Cleanup
    psql(`DELETE FROM invite_codes WHERE code = 'USED-INVITE-CODE-E2E'`);
  });

  test('env-var controlled settings are locked and cannot be saved', async ({ page }) => {
    await page.goto('/admin');
    await page.waitForURL('/admin', { timeout: 10000 });
    await expect(page.getByText('Application Settings')).toBeVisible({ timeout: 10000 });

    // ENABLE_BARCODE is set via env var (ENABLE_BARCODE=true in compose.test.yml).
    // The admin UI should render the select as disabled when source === 'env'.
    const barcodeLabel = page.getByText('ENABLE_BARCODE');
    await barcodeLabel.scrollIntoViewIfNeeded();
    await expect(barcodeLabel).toBeVisible({ timeout: 5000 });

    const barcodeSelect = barcodeLabel.locator('..').locator('select');
    await expect(barcodeSelect).toBeVisible({ timeout: 5000 });
    await expect(barcodeSelect).toBeDisabled({ timeout: 5000 });

    // The container should carry the "Locked — set via environment variable" title attribute
    const barcodeContainer = barcodeLabel.locator('..');
    const containerTitle = await barcodeContainer.getAttribute('title');
    expect(containerTitle).toContain('environment variable');

    // Attempting to save the env-controlled setting via the API directly should be rejected
    const csrfRes = await page.request.get('/api/me');
    const csrfToken = csrfRes.headers()['x-csrf-token'] || '';

    const saveRes = await page.request.post('/admin/settings', {
      data: { settings: { enable_barcode: 'false' } },
      headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
    });
    // Backend rejects changes to env-controlled settings
    expect(saveRes.status()).toBe(400);
    const body = await saveRes.json();
    expect(body.error || body.message || '').toMatch(/environment variable/i);
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

    // Unused invite: should show a Delete button and Copy Link (no "Used by")
    const unusedRow = page.locator('div').filter({ hasText: 'E2E-UNUSED-CODE' }).first();
    await unusedRow.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(unusedRow).toBeVisible({ timeout: 5000 });
    await expect(unusedRow.locator('button', { hasText: 'Delete' })).toBeVisible({ timeout: 3000 });
    await expect(unusedRow.getByText(/Copy Link/i)).toBeVisible({ timeout: 3000 });

    // Used invite: should show "Used by" and no Delete button
    const usedRow = page.locator('div').filter({ hasText: 'E2E-USED-CODE' }).first();
    await usedRow.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(usedRow).toBeVisible({ timeout: 5000 });
    await expect(usedRow.getByText(/Used by/i)).toBeVisible({ timeout: 3000 });
    await expect(usedRow.locator('button', { hasText: 'Delete' })).not.toBeVisible({ timeout: 2000 });

    // Expired invite: should show an expiry indicator (red "expires" text via CSS class)
    const expiredRow = page.locator('div').filter({ hasText: 'E2E-EXPIRED-CODE' }).first();
    await expiredRow.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(expiredRow).toBeVisible({ timeout: 5000 });
    await expect(expiredRow.getByText(/expires/i)).toBeVisible({ timeout: 3000 });

    // Cleanup
    psql(`DELETE FROM invite_codes WHERE code IN ('E2E-UNUSED-CODE', 'E2E-USED-CODE', 'E2E-EXPIRED-CODE')`);
  });
});
