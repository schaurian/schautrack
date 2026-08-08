import { test as setup, expect } from '@playwright/test';
import { execSync } from 'child_process';

const AUTH_FILE = 'e2e/.auth/user.json';

/**
 * Re-seed the shared test users.
 *
 * This is DESTRUCTIVE and GLOBAL: setup-test-user.ts rewrites the password hash
 * of test@test.com, link-test@test.com, admin@test.com, florian@schauer.to and
 * 2fa@test.com, forces `email_verified`, sets `totp_enabled = false` and
 * `totp_secret = NULL`, drops every row in totp_backup_codes for those users,
 * wipes test@test.com's entries / weights / todos / notes, deletes the account
 * links between them and resets the enable_registration and enable_barcode
 * admin settings. Every project in the suite owns some of that state.
 *
 * It therefore has to run where nothing can observe it half-applied, and the
 * `setup` project is the only such place: `dependencies` makes Playwright run a
 * dependency project to completion before any dependent starts, and every other
 * project depends on `setup` directly or transitively — `shutdown` excepted, and
 * that one touches no shared user by construction (see its file header).
 *
 * It used to live in `admin-setup` instead, which declares `dependencies:
 * ['setup']` exactly like `2fa`, `auth`, `stepup`, `passkey` and `chromium` do.
 * Sibling projects are not ordered against each other, so the re-seed ran
 * CONCURRENTLY with the specs that own the rows it was rewriting. two-factor.spec
 * is `mode: 'serial'` — it enables 2FA in one test and logs back in in the next —
 * so a re-seed landing between the two flipped `totp_enabled` back to false, the
 * server took the non-2FA branch of POST /api/auth/login, the client went
 * straight to /dashboard, and `getByLabel('2FA Code')` matched nothing at all.
 * That is #461. The same window could equally wipe an entry, a todo or a link
 * out from under the project that had just written it.
 *
 * Running it here also keeps the safety net it was added for: `scripts/e2e.sh`
 * and `npm run test:e2e:setup` both seed before Playwright starts, but a bare
 * `npx playwright test` against an already-running stack does not, and that is
 * still a normal way to iterate on a spec.
 *
 * A failure is reported and swallowed rather than fatal. The seed needs `docker
 * exec` against the DB container, which a run driven at a remote E2E_BASE_URL
 * cannot do even though its users are already seeded; failing hard there would
 * break a working setup. When the seed genuinely was needed, the login below
 * fails immediately and points at the same problem.
 */
function seedTestUsers() {
  try {
    execSync('npx tsx e2e/setup-test-user.ts', { stdio: 'pipe', timeout: 60000 });
  } catch (err) {
    const e = err as { stderr?: Buffer; stdout?: Buffer; message?: string };
    const detail = (e.stderr?.toString() || e.stdout?.toString() || e.message || '').trim();
    console.warn(`[setup] seeding test users failed, continuing with the database as-is:\n${detail}`);
  }
}

setup('authenticate', async ({ page }) => {
  // Before the login, not after: the seed rewrites this user's password hash.
  seedTestUsers();

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');

  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();

  await page.waitForURL('/dashboard', { timeout: 15000 });

  // Save session for all parallel workers to reuse
  await page.context().storageState({ path: AUTH_FILE });
});
