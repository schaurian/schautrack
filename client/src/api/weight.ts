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
 * `body_fat` is three-state on the server: omit the key to leave a stored
 * reading untouched, send null to clear it, send a number to set it. Callers
 * that only deal in weight must omit it rather than sending null.
 */
export function upsertWeight(data: { date: string; weight: number; body_fat?: number | null }) {
  return api<{ ok: boolean }>('/weight/upsert', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteWeight(id: number) {
  return api<{ ok: boolean }>(`/weight/${id}/delete`, { method: 'POST' });
}
