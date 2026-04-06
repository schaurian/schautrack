import { test, expect } from '@playwright/test';

test('sitemap.xml returns valid XML', async ({ page }) => {
  const response = await page.request.get('/sitemap.xml');
  expect(response.ok()).toBeTruthy();
  const text = await response.text();
  expect(text).toContain('<?xml');
  expect(text).toContain('<urlset');
});
