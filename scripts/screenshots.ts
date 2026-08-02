/**
 * Captures the README screenshots from the seeded demo account.
 *
 *   npm run screenshots          # stack + seed + capture (see package.json)
 *   npx tsx scripts/screenshots.ts   # capture only, against a running stack
 *
 * Writes docs/screenshots/*.png. dashboard.png is the README hero and is just
 * the desktop dashboard under its historical name, so the README keeps working.
 */
import { chromium, type Page } from '@playwright/test';
import { mkdirSync } from 'fs';

const BASE = process.env.SCREENSHOT_BASE_URL || 'http://localhost:3001';
const OUT = 'docs/screenshots';
const EMAIL = 'demo@schautrack.app';
const PASSWORD = 'demo1234demo';

const DESKTOP = { width: 1280, height: 900 };
const MOBILE = { width: 390, height: 844 };

async function login(page: Page) {
  await page.goto(`${BASE}/login`);
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  const captcha = page.getByLabel(/captcha|challenge/i).first();
  if (await captcha.isVisible({ timeout: 800 }).catch(() => false)) await captcha.fill('1');
  await page.getByRole('button', { name: 'Log In', exact: true }).click();
  await page.waitForURL(/dashboard/, { timeout: 20000 });
  await settle(page);
}

/**
 * Wait for the view to stop moving. The rings and macro bars animate their
 * width/stroke on mount, so capturing too early freezes them mid-sweep.
 */
async function settle(page: Page) {
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(1200);
}

async function shot(page: Page, name: string, fullPage = false) {
  await settle(page);
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage });
  console.log(`  ${OUT}/${name}.png${fullPage ? ' (full page)' : ''}`);
}

/**
 * Crop from the top of the page down to the bottom of `endAt`, so the hero
 * ends on a section boundary instead of slicing a card in half. Falls back to
 * a plain viewport shot if the anchor isn't on the page.
 */
async function shotThrough(page: Page, name: string, endAt: string) {
  await settle(page);
  const box = await page.locator(endAt).first().boundingBox().catch(() => null);
  const clip = box ? { x: 0, y: 0, width: page.viewportSize()!.width, height: Math.ceil(box.y + box.height + 10) } : undefined;
  // fullPage as well, or a clip taller than the viewport gets capped at the fold.
  await page.screenshot({ path: `${OUT}/${name}.png`, clip, fullPage: true });
  console.log(`  ${OUT}/${name}.png${clip ? ` (cropped to ${clip.height}px)` : ''}`);
}

(async () => {
  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  console.log(`capturing from ${BASE}`);

  // ---- desktop -----------------------------------------------------------
  const desktop = await browser.newPage({ viewport: DESKTOP, deviceScaleFactor: 2 });
  await desktop.goto(`${BASE}/`);
  await shot(desktop, 'landing-desktop');

  await login(desktop);
  await shot(desktop, 'dashboard-desktop', true);
  // The README hero has always been docs/screenshots/dashboard.png. End it at
  // the timeline so the frame closes on a whole card.
  await shotThrough(desktop, 'dashboard', 'section:has-text("Timeline")');

  await desktop.goto(`${BASE}/plan`);
  await shot(desktop, 'plan-desktop', true);

  await desktop.goto(`${BASE}/settings`);
  await shot(desktop, 'settings-desktop', true);

  // ---- mobile ------------------------------------------------------------
  const mobile = await browser.newPage({ viewport: MOBILE, deviceScaleFactor: 3 });
  await login(mobile);
  await shot(mobile, 'dashboard-mobile');

  await mobile.goto(`${BASE}/plan`);
  await shot(mobile, 'plan-mobile', true);

  await mobile.goto(`${BASE}/settings`);
  await shot(mobile, 'settings-mobile');

  // The add sheet, with the quick-add chips visible.
  await mobile.goto(`${BASE}/dashboard`);
  await settle(mobile);
  await mobile.getByRole('button', { name: 'Add food' }).click();
  await mobile.getByRole('dialog', { name: 'Add food' }).waitFor({ timeout: 10000 });
  await shot(mobile, 'add-sheet-mobile');

  await browser.close();
})();
