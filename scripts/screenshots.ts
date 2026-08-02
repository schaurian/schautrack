/**
 * Captures the README screenshots from the seeded demo account.
 *
 *   npm run screenshots          # stack + seed + capture (see package.json)
 *   npx tsx scripts/screenshots.ts   # capture only, against a running stack
 *
 * Writes docs/screenshots/*.png. dashboard.png is the README hero and is just
 * the desktop dashboard under its historical name, so the README keeps working.
 */
import { chromium, type Page, type Browser } from '@playwright/test';
import { mkdirSync, readFileSync } from 'fs';

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


/**
 * Compose the README hero: the desktop app with two phones in front of it.
 *
 * Rendered as a page and screenshotted rather than stitched with an image
 * library — the browser is already here, and CSS gives us rounded corners,
 * bezels and shadows for free. Both source images are inlined so the page has
 * no external requests to wait on.
 */
async function composeHero(browser: Browser) {
  const inline = (file: string) => `data:image/png;base64,${readFileSync(`${OUT}/${file}`).toString('base64')}`;

  const html = `<!doctype html><html><head><meta charset="utf-8"><style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { width: 1600px; height: 900px; background: #04060d; display: grid; place-items: center; }
    /* Same glows as the app's own background, so the frame feels like part of it. */
    .stage {
      position: relative; width: 1600px; height: 900px; overflow: hidden;
      background:
        radial-gradient(circle at 76% 6%, rgba(168, 85, 247, 0.17), transparent 46%),
        radial-gradient(circle at 10% 92%, rgba(14, 165, 233, 0.14), transparent 44%),
        linear-gradient(160deg, #060a16 0%, #080e1f 55%, #05070f 100%);
    }
    .desktop {
      position: absolute; right: 60px; top: 130px; width: 1010px; height: 616px;
      overflow: hidden; border-radius: 18px;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.09), 0 40px 90px rgba(0,0,0,0.7);
    }
    .desktop img { width: 100%; display: block; }
    /* No fixed height: at this width the phone screenshot fits whole, so the
       frame never cuts through a card. */
    .phone {
      position: absolute; width: 250px; overflow: hidden;
      border-radius: 38px; border: 8px solid #0d1226; background: #0d1226;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.11), 0 34px 74px rgba(0,0,0,0.75);
    }
    .phone img { width: 100%; display: block; }
    .phone-back { left: 70px; top: 140px; }
    .phone-front { left: 310px; top: 285px; }
  </style></head><body>
    <div class="stage">
      <div class="desktop"><img src="${inline('dashboard.png')}"></div>
      <div class="phone phone-back"><img src="${inline('dashboard-mobile.png')}"></div>
      <div class="phone phone-front"><img src="${inline('add-sheet-mobile.png')}"></div>
    </div>
  </body></html>`;

  const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 2 });
  await page.setContent(html, { waitUntil: 'load' });
  await page.locator('.stage').screenshot({ path: `${OUT}/hero.png` });
  await page.close();
  console.log(`  ${OUT}/hero.png (composed)`);
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

  await composeHero(browser);

  await browser.close();
})();
