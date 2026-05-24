import { api } from './client';
import type { Entry, SavedFood } from '@/types';

export interface SavedFoodPayload {
  name?: string;
  emoji?: string | null;
  amount?: number | null;
  protein_g?: number | null;
  carbs_g?: number | null;
  fat_g?: number | null;
  fiber_g?: number | null;
  sugar_g?: number | null;
}

export function listSavedFoods() {
  return api<{ ok: boolean; savedFoods: SavedFood[] }>('/api/saved-foods');
}

export function createSavedFood(data: SavedFoodPayload) {
  return api<{ ok: boolean; savedFood: SavedFood }>('/api/saved-foods', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function updateSavedFood(id: number, data: SavedFoodPayload) {
  return api<{ ok: boolean; savedFood: SavedFood }>(`/api/saved-foods/${id}/update`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteSavedFood(id: number) {
  return api<{ ok: boolean }>(`/api/saved-foods/${id}/delete`, { method: 'POST' });
}

export function trackSavedFood(id: number, entryDate?: string) {
  return api<{ ok: boolean; entry: Entry }>(`/api/saved-foods/${id}/track`, {
    method: 'POST',
    body: JSON.stringify({ entry_date: entryDate || '' }),
  });
}

export function saveEntryAsFood(entryId: number, options?: { emoji?: string | null }) {
  return api<{ ok: boolean; savedFood: SavedFood }>(`/api/entries/${entryId}/save-as-food`, {
    method: 'POST',
    body: JSON.stringify(options ?? {}),
  });
}
