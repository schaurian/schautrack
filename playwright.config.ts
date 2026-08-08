import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

export default defineConfig({
  testDir: './e2e',
  // `*.helper.spec.ts` is reserved for ad-hoc, non-asserting browser automation
  // (screenshot capture and the like) and is never part of a run. Screenshots are
  // produced by `npm run screenshots` (scripts/screenshots.ts), not by a spec;
  // e2e/ holds asserting specs only.
  //
  // NOTE: a project that sets its own `testIgnore` REPLACES this list rather than
  // extending it, so the pattern is repeated in the `chromium` project below —
  // that is the only project selecting files by ignore rather than `testMatch`.
  testIgnore: ['**/fixtures/**', '**/setup-test-user.ts', '**/*.helper.spec.ts'],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 1,
  workers: process.env.CI ? 2 : Math.min(4, require('os').cpus().length || 4),
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 60000,
  expect: { timeout: 10000 },

  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    // Setup: re-seed the shared test users, then log in as the main one and
    // save the session.
    //
    // This project is the ONLY place a destructive, suite-wide database write
    // may live, and everything below is what makes that true: `dependencies`
    // runs a dependency project to completion before any dependent starts, and
    // every other project depends on `setup` directly or transitively —
    // `shutdown` excepted, and that one signals a throwaway container clone and
    // touches no shared user. So a write here cannot be observed half-applied.
    //
    // The corollary is the maintenance rule: a seed, a truncate or any other
    // rewrite of state a spec elsewhere owns belongs HERE and nowhere else.
    // Putting it in a project that has siblings — anything that merely declares
    // `dependencies: ['setup']`, i.e. admin-setup, auth, 2fa, stepup, passkey
    // and chromium — makes it race by design, because siblings are not ordered
    // against each other. That is exactly what #461 was. Enforced by
    // TestSeedIsInvokedOnlyFromGlobalSetup in internal/e2eguard.
    {
      name: 'setup',
      testMatch: /global-setup\.ts/,
    },
    // Admin setup: login as admin user, save session. Seeds nothing — see above.
    {
      name: 'admin-setup',
      testMatch: /admin-setup\.ts/,
      dependencies: ['setup'],
    },
    // Auth tests: need fresh contexts (no saved session)
    {
      name: 'auth',
      testMatch: /auth\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // 2FA tests: need fresh contexts and run serially
    {
      name: '2fa',
      testMatch: /two-factor\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // Step-up tests: need fresh contexts (each test logs in fresh to control
    // grace-window state).
    {
      name: 'stepup',
      testMatch: /stepup\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // Passkey tests: need fresh contexts + virtual WebAuthn authenticator.
    {
      name: 'passkey',
      testMatch: /passkey\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
    // ---------------------------------------------------------------------
    // The admin_settings lane.
    //
    // Three admin_settings rows are global, mutable and observable by every
    // request: enable_barcode, enable_legal and enable_registration. A spec
    // that FLIPS one corrupts any spec that READS it while the flip is in
    // effect, and those windows are seconds wide (a login, a page load and an
    // assertion) — not something a retry hides.
    //
    // `dependencies` is Playwright's only cross-project ordering primitive and
    // it couples ordering to SUCCESS: a project is skipped outright unless
    // every test of every project it depends on passed (flaky-then-green is
    // fine, retry-exhausted is not), and its tests are then reported merely as
    // "did not run". There is no order-only variant. So every edge below costs
    // blast radius, and each one has to be paid for by a real conflict.
    //
    //   admin ─► admin-settings ─► invite ─► settings-readers
    //   \___________ writers ____________/   \___ readers ___/
    //
    // Everything that touches those three flags lives in this one serial lane,
    // writers first and readers last. `chromium` contains neither a writer nor
    // a reader, so nothing depends on it — which is the whole point. It used to
    // sit upstream of the lane, and one retry-exhausted test out of its 212
    // silently deleted all 13 tests in admin-settings, invite and shutdown
    // (see #377). Nothing outside the lane gates anything now.
    //
    // Readers are at the TAIL rather than the head deliberately. Either end
    // satisfies the isolation requirement, but the tail is the safe end: a
    // reader that hard-fails there costs only itself, whereas at the head it
    // would delete the whole lane behind it. mobile-shell.spec in particular is
    // the flakiest file in the suite and must never gate anything.
    //
    // MAINTENANCE: a spec that reads enable_barcode / enable_legal /
    // enable_registration belongs in `settings-readers`, not in `chromium`; a
    // spec that writes one belongs in `admin`, `admin-settings` or `invite`.
    // Getting it wrong buys a rare, unattributable flake, so check this when a
    // spec starts visiting /register or the barcode scanner.
    // ---------------------------------------------------------------------
    // Writer. admin.spec's "toggle registration mode" and "toggle barcode
    // feature" tests flip enable_registration and enable_barcode for several
    // seconds each, so it belongs in the lane — before this it sat outside any
    // ordering and raced the register/barcode specs in `chromium` outright.
    {
      name: 'admin',
      testMatch: /admin\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/admin.json',
      },
      dependencies: ['admin-setup'],
    },
    // Writers: barcode-extended flips enable_barcode, legal flips enable_legal.
    {
      name: 'admin-settings',
      testMatch: [/barcode-extended\.spec\.ts/, /legal\.spec\.ts/],
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['admin'],
    },
    // Invite tests register through the UI and flip enable_registration. Run
    // them strictly AFTER the legal tests so enable_legal is in its final
    // (true) state and the register form's consent checkboxes are deterministic
    // instead of racing the legal.spec toggles.
    {
      name: 'invite',
      testMatch: /invite-code\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['admin-settings'],
    },
    // Readers, last in the lane — every writer above has restored its flag by
    // now (each through the admin API, so the server's one-minute settings
    // cache is invalidated rather than waited out):
    //   barcode.spec            — needs enable_barcode=true (the scan button)
    //   mobile-shell.spec       — same, for the scanner-above-sheet test
    //   register.spec           — needs registration open (no invite field)
    //   email-verification.spec — registers through the UI, so it needs open
    //                             registration AND a stable enable_legal: the
    //                             consent flags are enforced server-side at
    //                             submit, long after the form was rendered.
    // Same `use` as `chromium`: barcode.spec rides the shared session, the
    // other three build their own contexts.
    {
      name: 'settings-readers',
      testMatch: [/barcode\.spec\.ts/, /mobile-shell\.spec\.ts/, /register\.spec\.ts/, /email-verification\.spec\.ts/],
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/user.json',
      },
      dependencies: ['invite'],
    },
    // Graceful shutdown. No dependencies: the spec signals a throwaway clone of
    // the web container rather than the container the suite is using, so it has
    // no global side effect and no longer has to run last. See the file header.
    {
      name: 'shutdown',
      testMatch: /graceful-shutdown\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    // Everything else: parallel with shared session. Nothing depends on this
    // project, so a failure here costs exactly the failing test. This list
    // REPLACES the top-level `testIgnore`, so `**/*.helper.spec.ts` has to be
    // repeated here.
    {
      name: 'chromium',
      testIgnore: [/auth\.spec\.ts/, /two-factor\.spec\.ts/, /stepup\.spec\.ts/, /passkey\.spec\.ts/, /admin\.spec\.ts/, /barcode\.spec\.ts/, /mobile-shell\.spec\.ts/, /register\.spec\.ts/, /email-verification\.spec\.ts/, /barcode-extended\.spec\.ts/, /legal\.spec\.ts/, /invite-code\.spec\.ts/, /graceful-shutdown\.spec\.ts/, /\.helper\.spec\.ts$/, /fixtures\//],
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
});
