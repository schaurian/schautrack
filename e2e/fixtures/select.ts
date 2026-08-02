import { expect, type Locator, type Page } from '@playwright/test';

/**
 * Helpers for the Radix-based <Select> (client/src/components/ui/select.tsx).
 *
 * It renders a button trigger + a portalled listbox instead of a native
 * <select>, so `selectOption()` / `inputValue()` / `toHaveValue()` don't apply.
 * The trigger mirrors the current value onto `data-value`, and each option
 * carries `data-value`, which is what these helpers drive.
 */

/** Open `trigger` and pick the option with the given value. */
export async function chooseOption(page: Page, trigger: Locator, value: string) {
  await trigger.scrollIntoViewIfNeeded();
  await trigger.click();
  await page.locator(`[role="option"][data-value="${value}"]`).click();
  await expect(trigger).toHaveAttribute('data-value', value, { timeout: 5000 });
}

/** Current value of a select trigger. */
export async function selectedValue(trigger: Locator): Promise<string> {
  return (await trigger.getAttribute('data-value')) ?? '';
}

/** Assert the select's current value. */
export async function expectSelectValue(trigger: Locator, value: string, timeout = 5000) {
  await expect(trigger).toHaveAttribute('data-value', value, { timeout });
}
