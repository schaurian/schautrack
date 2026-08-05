import { test, expect, request, type Page } from '@playwright/test';
import { createIsolatedUser, expireStepUpGrace, loginUser, psql } from './fixtures/helpers';
import { completeStepUp } from './fixtures/stepup';

const BASE = process.env.E2E_BASE_URL || 'http://localhost:3001';

/**
 * The API-token card on /account, driven through the real UI.
 *
 * The point of this spec is the seam nothing else covers: a token minted by a
 * human clicking buttons has to actually authenticate a real /api/v1 request.
 * Unit tests cover the token service, and the Go handler tests cover the API,
 * but neither proves the browser flow produces a working credential — the
 * secret is shown exactly once and never re-fetchable, so if the UI drops it,
 * the failure is silent and unrecoverable.
 *
 * Each test uses a fresh login so the step-up grace window is in a known
 * state; token creation is step-up gated.
 */
// Serial: every test shares one user and wipes its tokens in beforeEach, so
// running them in parallel makes each one delete the tokens the others are
// mid-way through asserting on.
test.describe.configure({ mode: 'serial' });

/**
 * An HTTP client carrying ONLY the bearer token.
 *
 * storageState is blanked deliberately. The project-level storageState would
 * otherwise attach the logged-in session cookie, and then "the token
 * authenticates this request" would be unproven — the cookie could be doing
 * the work. With no cookie, a 200 can only be the token.
 */
async function apiClient(token: string) {
  return request.newContext({
    baseURL: BASE,
    storageState: { cookies: [], origins: [] },
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  });
}


test.describe('API tokens', () => {
  let user: { email: string; password: string; id: string };

  test.beforeAll(() => {
    user = createIsolatedUser('api-tokens');
  });

  test.beforeEach(() => {
    // Start every test from zero tokens so list assertions are exact rather
    // than "contains", which would pass even if creation silently duplicated.
    psql(`DELETE FROM api_tokens WHERE user_id = ${user.id}`);

    // Suppress the welcome tour. createIsolatedUser leaves
    // onboarding_completed_at NULL, so the tour auto-opens and its dialog
    // covers the token card — every click below would hit the overlay
    // instead. Same suppression onboarding.spec.ts uses.
    psql(`UPDATE users SET onboarding_completed_at = NOW() WHERE id = ${user.id}`);
  });

  /** Open /account and scroll the token card into view. */
  async function openTokenCard(page: Page) {
    await page.goto('/account');
    await page.waitForURL('/account');
    const heading = page.getByRole('heading', { name: 'API tokens' });
    await heading.scrollIntoViewIfNeeded();
    await expect(heading).toBeVisible();
  }

  /**
   * Fill and submit the create-token form. Returns the raw secret shown in the
   * one-time reveal panel.
   */
  async function createToken(page: Page, name: string, scopes: string[]): Promise<string> {
    await page.getByRole('button', { name: 'New token' }).click();
    await page.getByPlaceholder(/What is this token for/i).fill(name);

    for (const scope of scopes) {
      // Each scope renders as a label wrapping a checkbox and a <code> with
      // the scope name — click the checkbox inside the label that names it.
      await page.locator('label', { hasText: scope }).getByRole('checkbox').check();
    }

    await page.getByRole('button', { name: 'Create token' }).click();

    const secret = page.getByTestId('api-token-secret');
    await expect(secret).toBeVisible({ timeout: 10000 });
    return ((await secret.textContent()) || '').trim();
  }

  test('a token minted through the UI authenticates a real API request', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);
    const token = await createToken(page, 'Playwright entries', ['entries:write']);

    expect(token).toMatch(/^stk_[A-Za-z0-9_-]{43}$/);

    // The actual payoff: does this credential work against the public API?
    const api = await apiClient(token);

    const me = await api.get('/api/v1/me');
    expect(me.status()).toBe(200);
    const body = await me.json();
    expect(body.user.email).toBe(user.email);
    expect(body.token.scopes).toEqual(['entries:write']);

    // And it can actually write, with the scope it was granted.
    const created = await api.post('/api/v1/entries', {
      data: { calories: 321, name: 'From a UI-minted token' },
    });
    expect(created.status()).toBe(201);
    expect((await created.json()).calories).toBe(321);

    await api.dispose();
    await context.close();
  });

  test('scope checkboxes are enforced server-side', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);
    // Grant weight only — entries must then be refused.
    const token = await createToken(page, 'Playwright weight only', ['weight:read']);

    const api = await apiClient(token);

    expect((await api.get('/api/v1/weight')).status()).toBe(200);

    const denied = await api.get('/api/v1/entries');
    expect(denied.status()).toBe(403);
    // The 403 must name what is missing, or the user has to guess which
    // checkbox they forgot.
    const problem = await denied.json();
    expect(problem.required_scope).toBe('entries:read');
    expect(denied.headers()['content-type']).toContain('application/problem+json');

    await api.dispose();
    await context.close();
  });

  test('the secret is shown once and never again', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);
    const token = await createToken(page, 'Playwright once', ['plan:read']);

    // Dismissing the reveal panel drops the only copy.
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByTestId('api-token-secret')).toHaveCount(0);

    // A reload must not resurrect it. The list shows the short prefix only.
    await page.reload();
    await page.getByRole('heading', { name: 'API tokens' }).scrollIntoViewIfNeeded();
    await expect(page.getByText('Playwright once')).toBeVisible();
    expect(await page.content()).not.toContain(token);

    await context.close();
  });

  test('revoking through the UI kills the token immediately', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);
    const token = await createToken(page, 'Playwright revoke', ['entries:read']);
    await page.getByRole('button', { name: 'Done' }).click();

    const api = await apiClient(token);
    expect((await api.get('/api/v1/me')).status()).toBe(200);

    // Revoke is a plain button with no confirm dialog — deliberately, so the
    // kill switch is always one click away.
    await page.getByRole('button', { name: 'Revoke' }).click();
    await expect(page.getByText('Playwright revoke')).toHaveCount(0, { timeout: 10000 });

    const after = await api.get('/api/v1/me');
    expect(after.status()).toBe(401);

    await api.dispose();
    await context.close();
  });

  test('minting re-prompts for step-up once the grace window has expired', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);

    // A token is a long-lived credential for the whole account, so creating
    // one is gated like any other credential change.
    expireStepUpGrace(user.id);

    await page.getByRole('button', { name: 'New token' }).click();
    await page.getByPlaceholder(/What is this token for/i).fill('Playwright step-up');
    await page.locator('label', { hasText: 'entries:read' }).getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Create token' }).click();

    // The modal intercepts, and completing it retries the original request —
    // the token still gets created.
    await completeStepUp(page, user.password);

    const secret = page.getByTestId('api-token-secret');
    await expect(secret).toBeVisible({ timeout: 10000 });
    expect(((await secret.textContent()) || '').trim()).toMatch(/^stk_/);

    await context.close();
  });

  test('the scope list is served by the API, not hardcoded in the client', async ({ browser }) => {
    const { context, page } = await loginUser(browser, user.email, user.password);

    await openTokenCard(page);
    await page.getByRole('button', { name: 'New token' }).click();

    // Whatever the server grants must be offered — a client-side copy would
    // drift the moment a scope is added.
    const res = await fetch(`${BASE}/api/v1/openapi.json`);
    const spec = await res.json() as { info: { description: string } };

    for (const scope of ['entries:read', 'entries:write', 'weight:read', 'plan:read']) {
      await expect(page.locator('label', { hasText: scope })).toBeVisible();
      // The same scope is documented in the published spec.
      expect(spec.info.description).toContain(scope);
    }

    await context.close();
  });
});
