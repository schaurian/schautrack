import type { Page } from '@playwright/test';

/**
 * When legal pages are enabled (enable_legal), registration requires accepting
 * the Terms and a separate health-data consent. Check both boxes when they are
 * rendered so registration flows work regardless of the instance's legal
 * state (fresh DB: off; after the legal specs or on a reused DB: on).
 */
export async function acceptConsentIfShown(page: Page) {
  const termsBox = page.getByLabel('Accept the Terms of Service and Privacy Policy');
  if (await termsBox.isVisible({ timeout: 2000 }).catch(() => false)) {
    await termsBox.check();
    await page.getByLabel('Consent to health data processing').check();
  }
}
