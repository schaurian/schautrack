import { test, expect } from '@playwright/test';

// This file tests public-facing pages and SEO. Most tests use fresh (unauthenticated)
// contexts even though the chromium project provides a storageState, because these
// scenarios specifically test guest-facing behavior.

test.describe('Public Pages & SEO', () => {
  test('landing page loads for guests', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/');
    await page.waitForLoadState('domcontentloaded');

    // Landing page should display the main headline and feature cards
    await expect(page.getByText(/track nutrition/i).or(page.getByText(/schautrack/i)).first()).toBeVisible({ timeout: 10000 });

    // Feature cards from Landing.tsx
    const featureHeadings = ['Simple Logging', 'AI Estimation', 'Share with Friends', 'Self-Hostable'];
    for (const heading of featureHeadings) {
      await expect(page.getByText(heading)).toBeVisible({ timeout: 5000 });
    }

    await context.close();
  });

  test('landing page shows login and register links', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/');
    await page.waitForLoadState('domcontentloaded');

    // Get Started button links to /register
    const getStarted = page.getByRole('link', { name: /get started/i });
    await expect(getStarted).toBeVisible({ timeout: 10000 });
    await expect(getStarted).toHaveAttribute('href', /\/register/);

    // The layout nav for guests should include a Login link
    const loginLink = page.getByRole('link', { name: /log in/i }).or(page.getByRole('link', { name: /login/i }));
    await expect(loginLink.first()).toBeVisible({ timeout: 5000 });

    await context.close();
  });

  test('SPA routing works for /login', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');

    // Login form should be present
    await expect(page.getByLabel('Email')).toBeVisible({ timeout: 10000 });
    await expect(page.getByLabel('Password')).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: /log in/i })).toBeVisible({ timeout: 5000 });

    // Should not have redirected to a 404
    await expect(page).not.toHaveURL(/\/404/);

    await context.close();
  });

  test('SPA routing works for /register', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.waitForLoadState('domcontentloaded');

    // Register page should load (not 404) — look for form elements
    await expect(page.getByLabel('Email')).toBeVisible({ timeout: 10000 });
    await expect(page).not.toHaveURL(/\/404/);

    await context.close();
  });

  test('protected route /settings redirects unauthenticated users to login', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/settings');
    // useRequireAuth redirects to /login when no session
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });

    await context.close();
  });

  test('protected route /dashboard redirects unauthenticated users to login', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });

    await context.close();
  });

  test('sitemap.xml returns valid XML sitemap content', async ({ page }) => {
    const response = await page.request.get('/sitemap.xml');
    // The app serves a sitemap — verify it returns 200 with XML content
    expect(response.status()).toBe(200);
    const body = await response.text();
    // Must contain XML declaration or urlset element
    const isValidSitemap = body.includes('<?xml') || body.includes('<urlset');
    expect(isValidSitemap).toBe(true);
  });

  test('robots.txt is served', async ({ page }) => {
    const response = await page.request.get('/robots.txt');
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain('User-agent');
  });

  test('health endpoint returns 200 with ok status', async ({ page }) => {
    const response = await page.request.get('/api/health');
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status', 'ok');
    expect(body).toHaveProperty('app', 'schautrack');
  });
});
