import { api } from './client';

export function getNote(date: string, userId?: number) {
  const params = new URLSearchParams({ date });
  if (userId) params.set('user', String(userId));
  return api<{ ok: boolean; content: string; enabled: boolean }>(`/api/notes/day?${params}`);
}

export function saveNote(date: string, content: string) {
  return api<{ ok: boolean }>('/api/notes', {
    method: 'POST',
    body: JSON.stringify({ date, content }),
  });
}

export function toggleNotesEnabled(enabled: boolean) {
  return api<{ ok: boolean; enabled: boolean }>('/api/notes/toggle-enabled', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}
