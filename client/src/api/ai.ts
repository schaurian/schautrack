import { api } from './client';

export function estimateCalories(data: { image: string; context?: string }) {
  return api<{
    ok: boolean;
    calories?: number;
    food?: string;
    confidence?: string;
    macros?: Record<string, number>;
    error?: string;
  }>('/api/ai/estimate', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}
