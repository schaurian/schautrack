# Schautrack TODO

## Bugs

### 1. AI settings don't indicate global key availability
- **Problem:** Settings page shows no hint that a global API key is configured. Users don't know AI works without setting their own key.
- **Fix:** Backend should send `hasGlobalAiKey: bool` to frontend. Settings UI shows "Global API key configured" when true and user has no personal key.
- **Files:** `internal/handler/api.go`, `client/src/pages/Settings/AISettings.tsx`

### 2. Entry names invisible with all 6 macros on mobile
- **Problem:** With all macros enabled, fixed-width columns total ~408px, exceeding mobile viewport. The flex-1 name column gets zero space.
- **Fix:** Consider horizontal scroll for rows, or abbreviate/hide lower-priority macro columns on mobile, or use a compact number format.
- **Files:** `client/src/pages/Dashboard/EntryList.tsx`

### 3. Horizontal scroll on mobile (Android webview)
- **Problem:** Dashboard allows left-right scrolling on Android. Layout padding + min-width constraints cause ~16px overflow.
- **Fix:** Audit `min-w-[320px]` in EntryList and Layout padding. Ensure no horizontal overflow on 320px viewport.
- **Files:** `client/src/pages/Dashboard/EntryList.tsx`, `client/src/components/Layout/Layout.tsx`

### 4. 2000 cal display issue on Android
- **Problem:** Calorie goal number may not render correctly on Android WebView.
- **Status:** Needs clarification on exact visual issue

## E2E Test Coverage Gaps

### 5. 2FA e2e tests
- **Priority:** High (security-critical)
- **Tests to add:** `e2e/2fa.spec.ts`
  - Enable TOTP, verify backup codes shown
  - Log out, log back in with TOTP code
  - Log in with a backup code
  - Disable 2FA
  - Regenerate backup codes
- **Challenge:** Need to generate TOTP codes in tests (use `otpauth` or `otplib` npm package)

### 6. Admin panel e2e tests
- **Priority:** High (security-critical)
- **Tests to add:** `e2e/admin.spec.ts`
  - Access admin panel as admin user
  - Non-admin cannot access admin routes
  - Toggle registration open/closed
  - Toggle barcode on/off
  - Configure global AI settings
  - Create invite code (with/without email)
  - Delete unused invite code
  - Delete a user (verify cascade)
- **Challenge:** Need to set `ADMIN_EMAIL` env var to match test user, or create a separate admin user

### 7. Export/import e2e tests
- **Priority:** Medium
- **Tests to add:** `e2e/export-import.spec.ts`
  - Create entries, export JSON, verify file downloads
  - Import JSON file, verify entries restored
- **Challenge:** Playwright file download/upload handling

### 8. Delete account e2e test
- **Priority:** Medium
- **Tests to add:** `e2e/delete-account.spec.ts`
  - Delete account with password confirmation
  - Verify redirect to landing page
  - Verify user can no longer log in
- **Challenge:** Need to create a throwaway user for this test

### 9. Forgot password e2e test
- **Priority:** Low (hard to test email flow)
- **Tests to add:** `e2e/forgot-password.spec.ts`
  - Request password reset, verify success message shown
  - Verify rate limiting on reset requests
- **Note:** Can't test the actual email link without SMTP interceptor

### 10. Email change e2e test
- **Priority:** Low (hard to test email flow)
- **Tests to add:** `e2e/email-change.spec.ts`
  - Request email change, verify pending state shown
  - Cancel pending email change
- **Note:** Same email limitation as forgot-password

## UI Improvements

### 11. Todo settings: move higher and improve look
- **Problem:** Todo settings are positioned low in settings page.
- **Fix:** Move TodoSettings higher in settings layout.
- **Files:** `client/src/pages/Settings/Settings.tsx`, `client/src/pages/Settings/TodoSettings.tsx`

---

## Suggested Order

1. **E2E tests:** #5 (2FA), #6 (admin panel) — security-critical coverage
2. **Bugs:** #1 (AI settings hint), #2 + #3 (mobile layout)
3. **More e2e:** #7 (export/import), #8 (delete account)
4. **UI:** #11 (todo settings position)
