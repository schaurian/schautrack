import { api } from './client';
import type { SettingsData } from '@/types';

export function getSettings() {
  return api<SettingsData>('/api/settings');
}

export function saveMacros(data: Record<string, string | boolean | number>) {
  return api<{ ok: boolean }>('/settings/macros', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function savePreferences(data: { weight_unit: string; timezone: string; language: string }) {
  return api<{ ok: boolean }>('/settings/preferences', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

// Step-up auth handles password+TOTP verification before this call lands;
// the body just carries the new password.
export function savePassword(data: { new_password: string; confirm_password: string }) {
  return api<{ ok: boolean; error?: string }>('/settings/password', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function saveAiSettings(data: Record<string, string>) {
  return api<{ ok: boolean }>('/settings/ai', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function setup2fa() {
  return api<{ ok: boolean; qrDataUrl?: string; secret?: string; otpauthUrl?: string }>('/2fa/setup', {
    method: 'POST',
  });
}

export function enable2fa(data: { token: string }) {
  return api<{ ok: boolean; error?: string; backupCodes?: string[] }>('/2fa/enable', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function disable2fa() {
  return api<{ ok: boolean; error?: string }>('/2fa/disable', { method: 'POST' });
}

export function regenerateBackupCodes() {
  return api<{ ok: boolean; error?: string; backupCodes?: string[] }>('/2fa/backup-codes', {
    method: 'POST',
  });
}

export function requestEmailChange(data: { new_email: string }) {
  return api<{ ok: boolean; error?: string }>('/settings/email/request', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function verifyEmailChange(data: { code: string }) {
  return api<{ ok: boolean; error?: string }>('/settings/email/verify', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function cancelEmailChange() {
  return api<{ ok: boolean }>('/settings/email/cancel', { method: 'POST' });
}

// Routed through api() so the step-up modal can intercept the 403 and retry
// after re-auth. FormData body is left untouched (api() only auto-sets
// Content-Type for string bodies, so the multipart boundary stays intact).
/** One row the server could not read, and why. `reason` is a stable code. */
export interface ImportSkippedRow {
  /** `entry` or `weight` — the two arrays are indexed separately. */
  kind: string;
  /** Position in that array in the uploaded file. */
  index: number;
  /** The row's date when it had a readable one; absent when the date is why it failed. */
  date?: string;
  /** `not_an_object` | `invalid_date` | `invalid_amount` | `invalid_weight` | `row_limit` */
  reason: string;
}

export interface ImportResult {
  ok: boolean;
  message?: string;
  error?: string;
  /** True when nothing was written. */
  dry_run?: boolean;
  skipped?: {
    /** Every dropped row, including those past the report cap. */
    total: number;
    /** How many are listed in `rows`. */
    reported: number;
    rows: ImportSkippedRow[];
  };
}

/**
 * @param dryRun Parse and report without writing. The real import DELETEs the
 * account's existing entries before inserting, so this is the only way to see
 * what a file would do while that is still reversible.
 */
export function importData(file: File, dryRun = false): Promise<ImportResult> {
  const formData = new FormData();
  formData.append('import_file', file);
  if (dryRun) formData.append('dry_run', 'true');
  return api<ImportResult>('/settings/import', {
    method: 'POST',
    body: formData,
  });
}

// Server returns the full export as JSON. The browser turns that into a
// download via a Blob URL; routing through api() is what lets the step-up
// modal intercept the 403 and retry on success.
export async function exportData(): Promise<void> {
  const data = await api('/settings/export', { method: 'POST' });
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `schautrack-export-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
