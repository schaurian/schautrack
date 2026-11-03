import { test, expect, type Page } from '@playwright/test';
import { createIsolatedUser, detectAdminEmail, loginUser, psql } from './fixtures/helpers';

// The admin user list shows each account's last login and sorts by it.
//
// Four isolated accounts with different histories: two sign in for real during
// the test (through POST /api/auth/login, so the timestamp is the server's own),
// one gets a back-dated login, and one has none recorded. Everything is
// asserted against those four only — the shared database holds every other
// spec's users too, so the search box narrows the list to this spec's prefix.
//
// Set E2E_SCREENSHOT_DIR to also save desktop and 390px screenshots.

const ADMIN_EMAIL = detectAdminEmail();
const ADMIN_PASSWORD = 'admin1234test';
const SHOTS = process.env.E2E_SCREENSHOT_DIR;

test.describe('Admin user list — last login', () => {
  test.describe.configure({ mode: 'serial' });

  let users: Record<'recent' | 'earlier' | 'old' | 'none', { email: string; password: string; id: string }>;

  test.beforeAll(async ({ browser }) => {
    users = {
      recent: createIsolatedUser('lastlogin-recent'),
      earlier: createIsolatedUser('lastlogin-earlier'),
      old: createIsolatedUser('lastlogin-old'),
      none: createIsolatedUser('lastlogin-none'),
    };
    // Accounts are reused across runs: start every history from scratch.
    psql(`UPDATE users SET last_login_at = NULL WHERE id IN (${Object.values(users).map((u) => u.id).join(',')})`);

    // Real sign-ins, in order: `earlier` first, then `recent`.
    for (const key of ['earlier', 'recent'] as const) {
      const { context } = await loginUser(browser, users[key].email, users[key].password);
      await context.close();
      await new Promise((r) => setTimeout(r, 1100));
    }
    psql(`UPDATE users SET last_login_at = NOW() - INTERVAL '40 days' WHERE id = ${users.old.id}`);
  });

  async function openAdmin(page: Page) {
    await page.goto('/admin');
    await expect(page.getByText('Users (')).toBeVisible({ timeout: 10000 });
    await page.getByPlaceholder('Search by email...').fill('e2e-lastlogin-');
  }

  async function order(page: Page): Promise<string[]> {
    const rows = page.getByTestId('admin-user-row');
    const texts = await rows.allTextContents();
    return texts.map((t) => {
      const key = (['recent', 'earlier', 'old', 'none'] as const).find((k) => t.includes(users[k].email));
      return key ?? '?';
    }).filter((k) => k !== '?');
  }

  function row(page: Page, key: keyof typeof users) {
    return page.getByTestId('admin-user-row').filter({ hasText: users[key].email });
  }

  test('real logins are recorded and the failed one is not', async () => {
    expect(psql(`SELECT last_login_at IS NOT NULL FROM users WHERE id = ${users.recent.id}`)).toBe('t');
    expect(psql(`SELECT last_login_at IS NOT NULL FROM users WHERE id = ${users.earlier.id}`)).toBe('t');

    const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
    const csrf = await fetch(`${baseURL}/api/csrf`);
    const sid = (csrf.headers.get('set-cookie') || '').match(/schautrack\.sid=([^;]+)/)?.[1] ?? '';
    const { token } = (await csrf.json()) as { token: string };
    const res = await fetch(`${baseURL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token, Cookie: `schautrack.sid=${sid}` },
      body: JSON.stringify({ email: users.none.email, password: 'definitely-wrong' }),
    });
    expect(res.status).toBe(401);
    expect(psql(`SELECT last_login_at IS NULL FROM users WHERE id = ${users.none.id}`)).toBe('t');
  });

  for (const viewport of [{ name: 'desktop', width: 1280, height: 900 }, { name: 'mobile', width: 390, height: 844 }]) {
    test(`column and both sort directions (${viewport.name})`, async ({ browser }) => {
      const { context, page } = await loginUser(browser, ADMIN_EMAIL, ADMIN_PASSWORD);
      try {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await openAdmin(page);

        // Accounts are per worker and reused across runs, so other workers'
        // copies may match the search too: look at this worker's four only.
        for (const key of ['recent', 'earlier', 'old', 'none'] as const) {
          await expect(row(page, key)).toHaveCount(1);
        }

        // The column: relative text, absolute time on hover, honest unknown.
        await expect(row(page, 'recent').getByTestId('admin-user-last-login')).toHaveText(/Last login (now|\d+ seconds? ago|1 minute ago|\d+ minutes ago)/);
        await expect(row(page, 'old').getByTestId('admin-user-last-login')).toHaveText(/Last login (last month|\d+ months? ago)/);
        const oldTitle = await row(page, 'old').locator('time').getAttribute('title');
        expect(oldTitle).toMatch(/\d{4}/);
        const none = row(page, 'none').getByTestId('admin-user-last-login');
        await expect(none).toContainText('Last login —');
        await expect(none).toHaveAttribute('title', 'No login recorded since this was introduced');

        // The row must fit at phone width: no horizontal scroll, delete button on screen.
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow).toBeLessThanOrEqual(0);
        const btn = await row(page, 'none').getByRole('button', { name: 'Delete' }).boundingBox();
        expect(btn).not.toBeNull();
        expect((btn?.x ?? 0) + (btn?.width ?? 0)).toBeLessThanOrEqual(viewport.width);

        const shot = async (name: string) => {
          if (!SHOTS) return;
          await page.getByText('Users (').evaluate((el) => el.scrollIntoView({ block: 'start' }));
          await page.evaluate(() => window.scrollBy(0, -24));
          await page.screenshot({ path: `${SHOTS}/${viewport.name}-${name}.png` });
        };
        await shot('default');

        await page.getByRole('radio', { name: 'Recent login' }).click();
        await expect.poll(() => order(page)).toEqual(['recent', 'earlier', 'old', 'none']);
        await shot('recent-login');

        await page.getByRole('radio', { name: 'Oldest login' }).click();
        await expect.poll(() => order(page)).toEqual(['old', 'earlier', 'recent', 'none']);
        await shot('oldest-login');

        // Back to the default.
        await page.getByRole('radio', { name: 'Newest' }).click();
        await expect(page.getByRole('radio', { name: 'Newest' })).toHaveAttribute('aria-checked', 'true');
      } finally {
        await context.close();
      }
    });
  }

  test('non-admin gets 403 from the sorted list', async ({ browser }) => {
    const { context, page } = await loginUser(browser, users.recent.email, users.recent.password);
    try {
      const res = await page.request.get('/api/admin?sort=last_login&order=desc');
      expect(res.status()).toBe(403);
      expect(await res.text()).not.toContain('last_login_at');
      const me = await page.request.get('/api/me');
      expect(await me.text()).not.toContain('last_login');
    } finally {
      await context.close();
    }
  });
});
