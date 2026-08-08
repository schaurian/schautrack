import { api } from './client';
import type { WeightEntry } from '@/types';

export function getWeightDay(date: string, userId?: number) {
  const qs = new URLSearchParams({ date });
  if (userId) qs.set('user', String(userId));
  return api<{ ok: boolean; entry: WeightEntry | null; lastWeight: WeightEntry | null }>(`/weight/day?${qs}`, {
    headers: { Accept: 'application/json' },
  });
}

/**
 * Both value fields are optional and omitting one leaves whatever is stored
 * alone, so a save only ever writes what the user actually entered.
 *
 * - `body_fat` is three-state: omit the key to keep a stored reading, send null
 *   to clear it, send a number to set it.
 * - `weight` is two-state (the column is NOT NULL, so it cannot be cleared):
 *   omit the key to keep the stored weight, send a number to replace it.
 *   Callers that only deal in body fat MUST omit it — restating a cached weight
 *   overwrites a newer one logged from another device. Omitting it on a date
 *   with no entry yet is an error: there is no weight to attach the reading to.
 *
 * At least one of the two must be present.
 */
export function upsertWeight(data: { date: string; weight?: number; body_fat?: number | null }) {
  return api<{ ok: boolean }>('/weight/upsert', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteWeight(id: number) {
  return api<{ ok: boolean }>(`/weight/${id}/delete`, { method: 'POST' });
}

export function toggleBodyFatEnabled(enabled: boolean) {
  return api<{ ok: boolean; enabled: boolean }>('/weight/toggle-body-fat', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}
