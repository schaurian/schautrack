import { test, expect } from '@playwright/test';

// These tests use fresh browser contexts with no stored session so that
// the rate-limiting / captcha session counters start clean.

test.describe('Captcha', () => {
  test('captcha appears after 3 failed login attempts', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');

    // Submit wrong credentials 3 times
    for (let i = 0; i < 3; i++) {
      await page.getByLabel('Email').fill('captcha-test@test.com');
      await page.getByLabel('Password').fill('wrongpassword123');
      await page.getByRole('button', { name: 'Log In' }).click();
      // Wait for the error to appear before the next attempt
      await expect(page.getByText(/Invalid credentials/i)).toBeVisible({ timeout: 5000 });
    }

    // After 3 failures the API sets requireCaptcha: true and returns captchaSvg.
    // The Login component renders the SVG inside an <img> tag.
    const captchaImg = page.locator('img[alt="Captcha"]');
    await expect(captchaImg).toBeVisible({ timeout: 5000 });

    // A captcha input field must also be present
    const captchaInput = page.getByLabel('Captcha');
    await expect(captchaInput).toBeVisible({ timeout: 5000 });

    await context.close();
  });

  test('login succeeds with captcha bypass value', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');

    // Trigger captcha with 3 failed attempts
    for (let i = 0; i < 3; i++) {
      await page.getByLabel('Email').fill('captcha-test@test.com');
      await page.getByLabel('Password').fill('wrongpassword123');
      await page.getByRole('button', { name: 'Log In' }).click();
      await expect(page.getByText(/Invalid credentials/i)).toBeVisible({ timeout: 5000 });
    }

    // Captcha must now be visible
    const captchaImg = page.locator('img[alt="Captcha"]');
    await expect(captchaImg).toBeVisible({ timeout: 5000 });

    // Fill in the captcha bypass value. CAPTCHA_BYPASS=true in the test env
    // means the server accepts "bypass" as a valid answer.
    const captchaInput = page.getByLabel('Captcha');
    await captchaInput.fill('bypass');

    // Submit with wrong credentials again — should fail with "Invalid credentials"
    // rather than "Invalid captcha", which proves the captcha itself was accepted.
    await page.getByLabel('Email').fill('captcha-test@test.com');
    await page.getByLabel('Password').fill('wrongpassword123');
    await page.getByRole('button', { name: 'Log In' }).click();

    // The server accepted the captcha — the error is now about credentials, not captcha
    await expect(page.getByText(/Invalid credentials/i)).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/Invalid captcha/i)).not.toBeVisible();

    await context.close();
  });
});
