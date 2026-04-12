import { api } from './client';
import type { WeightEntry } from '@/types';

export function getWeightDay(date: string, userId?: number) {
  const qs = new URLSearchParams({ date });
  if (userId) qs.set('user', String(userId));
  return api<{ ok: boolean; entry: WeightEntry | null; lastWeight: WeightEntry | null }>(`/weight/day?${qs}`, {
    headers: { Accept: 'application/json' },
  });
}

export function upsertWeight(data: { date: string; weight: number }) {
  return api<{ ok: boolean }>('/weight/upsert', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteWeight(id: number) {
  return api<{ ok: boolean }>(`/weight/${id}/delete`, { method: 'POST' });
}
