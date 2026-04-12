import { api } from './client';
import type { DashboardData, Entry } from '@/types';

export function getDashboard(params: { range?: number; start?: string; end?: string; day?: string }) {
  const qs = new URLSearchParams();
  if (params.range) qs.set('range', String(params.range));
  if (params.start) qs.set('start', params.start);
  if (params.end) qs.set('end', params.end);
  if (params.day) qs.set('day', params.day);
  return api<DashboardData>(`/api/dashboard?${qs}`);
}

export function getDayEntries(userId: number, date: string) {
  return api<{ ok: boolean; date: string; entries: Entry[] }>(`/entries/day?date=${date}&user=${userId}`, {
    headers: { Accept: 'application/json' },
  });
}

export function createEntry(data: {
  amount?: number;
  entry_name?: string;
  entry_date?: string;
  weight?: number;
  protein_g?: number;
  carbs_g?: number;
  fat_g?: number;
  fiber_g?: number;
  sugar_g?: number;
}) {
  return api<{ ok: boolean }>('/entries', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function updateEntry(id: number, data: Record<string, unknown>) {
  return api<{ ok: boolean; entry?: Entry }>(`/entries/${id}/update`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteEntry(id: number) {
  return api<{ ok: boolean }>(`/entries/${id}/delete`, { method: 'POST' });
}
