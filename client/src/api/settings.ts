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

export function savePreferences(data: { weight_unit: string; timezone: string }) {
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

export async function importData(file: File, csrfToken: string): Promise<{ ok: boolean; message?: string; error?: string }> {
  const formData = new FormData();
  formData.append('import_file', file);
  formData.append('_csrf', csrfToken);
  const res = await fetch('/settings/import', {
    method: 'POST',
    body: formData,
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrfToken, Accept: 'application/json' },
  });
  return res.json();
}
