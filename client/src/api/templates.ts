import { api } from './client';
import type { MealTemplate, MealTemplateInput } from '@/types';

export function listTemplates(favoritesOnly = false) {
  const qs = favoritesOnly ? '?favorites=true' : '';
  return api<{ ok: boolean; templates: MealTemplate[] }>(`/api/templates${qs}`);
}

export function createTemplate(data: MealTemplateInput) {
  return api<{ ok: boolean; id: number }>('/templates', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function updateTemplate(id: number, data: MealTemplateInput) {
  return api<{ ok: boolean }>(`/templates/${id}/update`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteTemplate(id: number) {
  return api<{ ok: boolean }>(`/templates/${id}/delete`, { method: 'POST' });
}

export function toggleTemplateFavorite(id: number, isFavorite?: boolean) {
  return api<{ ok: boolean; is_favorite: boolean }>(`/templates/${id}/favorite`, {
    method: 'POST',
    body: isFavorite === undefined ? undefined : JSON.stringify({ is_favorite: isFavorite }),
  });
}

export function applyTemplate(id: number, day?: string) {
  const qs = day ? `?day=${encodeURIComponent(day)}` : '';
  return api<{ ok: boolean; count: number; day: string }>(`/templates/${id}/apply${qs}`, {
    method: 'POST',
  });
}
