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

/**
 * Your own quick-add items.
 *
 * Used by the Manage dialog and the Settings counter, which must NOT see
 * borrowed foods: Manage would offer them for editing (and 404 on save) and the
 * counter would bill a friend's foods against your own 200-item cap.
 */
export function listSavedFoods() {
  return api<{ ok: boolean; savedFoods: SavedFood[] }>('/api/saved-foods');
}

/**
 * Your own quick-add items plus those linked friends share with you, each
 * carrying `owner`. Only the dashboard chip row wants this.
 */
export function listSavedFoodsWithShared() {
  return api<{ ok: boolean; savedFoods: SavedFood[] }>('/api/saved-foods?scope=all');
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

export function trackSavedFood(id: number, entryDate?: string, quantity?: number) {
  const body: { entry_date: string; quantity?: number } = { entry_date: entryDate || '' };
  if (quantity != null && quantity > 1) body.quantity = quantity;
  return api<{ ok: boolean; entry: Entry }>(`/api/saved-foods/${id}/track`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function saveEntryAsFood(entryId: number, options?: { emoji?: string | null }) {
  return api<{ ok: boolean; savedFood: SavedFood }>(`/api/entries/${entryId}/save-as-food`, {
    method: 'POST',
    body: JSON.stringify(options ?? {}),
  });
}
