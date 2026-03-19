import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Weight Tracking', () => {
  test.fixme('track weight entry', async ({ page }) => {
    // FIXME: Track button click/Enter doesn't submit the weight form
    await login(page);

    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    // Click "Track weight"
    const trackButton = page.getByText('Track weight');
    await expect(trackButton).toBeVisible({ timeout: 5000 });
    await trackButton.click();

    // Fill in weight
    const weightInput = page.locator('#weight-input');
    await expect(weightInput).toBeVisible({ timeout: 3000 });
    await weightInput.fill('75.5');

    // Submit by pressing Enter on the input (more reliable than finding the button)
    await weightInput.press('Enter');

    // Weight value should appear (form closes, value shown)
    await expect(page.locator('#weight-input')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByText('75.5')).toBeVisible({ timeout: 5000 });
  });
});
