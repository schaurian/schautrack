import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Navigation', () => {
  test('nav links work when logged in', async ({ page }) => {
    await login(page);

    // Click Settings
    await page.getByText('Settings').click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 5000 });

    // Click Dashboard
    await page.getByText('Dashboard').click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 5000 });
  });

  test('footer links work', async ({ page }) => {
    await login(page);

    // Scroll to footer
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    // Privacy link
    const privacyLink = page.getByText('Privacy');
    if (await privacyLink.isVisible().catch(() => false)) {
      await privacyLink.click();
      await expect(page).toHaveURL(/\/privacy/, { timeout: 5000 });
      await page.goBack();
    }

    // Terms link
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    const termsLink = page.getByText('Terms');
    if (await termsLink.isVisible().catch(() => false)) {
      await termsLink.click();
      await expect(page).toHaveURL(/\/terms/, { timeout: 5000 });
    }
  });

  test('landing page loads for unauthenticated users', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/');
    // Should see landing page or redirect to login
    await expect(page.getByText(/schautrack|log in|track/i).first()).toBeVisible({ timeout: 5000 });

    await context.close();
  });
});
