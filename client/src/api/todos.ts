import { api } from './client';
import type { Todo, TodoDay } from '@/types';

export function getTodos() {
  return api<{ ok: boolean; todos: Todo[] }>('/api/todos');
}

export function createTodo(data: { name: string; schedule: Todo['schedule']; time_of_day?: string | null }) {
  return api<{ ok: boolean; todo: Todo }>('/api/todos', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function updateTodo(id: number, data: { name?: string; schedule?: Todo['schedule']; time_of_day?: string | null; sort_order?: number }) {
  return api<{ ok: boolean; todo: Todo }>(`/api/todos/${id}/update`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function deleteTodo(id: number) {
  return api<{ ok: boolean }>(`/api/todos/${id}/delete`, {
    method: 'POST',
  });
}

export function getTodosDay(date: string, userId?: number) {
  const params = new URLSearchParams({ date });
  if (userId) params.set('user', String(userId));
  return api<{ ok: boolean; enabled: boolean; todos: TodoDay[] }>(`/api/todos/day?${params}`);
}

export function toggleTodo(id: number, date: string) {
  return api<{ ok: boolean; completed: boolean }>(`/api/todos/${id}/toggle`, {
    method: 'POST',
    body: JSON.stringify({ date }),
  });
}

export function toggleTodosEnabled(enabled: boolean) {
  return api<{ ok: boolean; enabled: boolean }>('/api/todos/toggle-enabled', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}
