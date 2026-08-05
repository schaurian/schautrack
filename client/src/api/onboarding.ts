import { api } from './client';

/** Marks the welcome tour as dismissed so it stops opening by itself. */
export function completeOnboarding() {
  return api<{ ok: boolean }>('/api/onboarding/complete', { method: 'POST' });
}
