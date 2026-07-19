import { api } from './client';
import type { PlanResponse, WeightGoal, BodyMetrics } from '@/types';

export function getPlan() {
  return api<PlanResponse>('/plan', {
    headers: { Accept: 'application/json' },
  });
}

export function updateMetrics(m: BodyMetrics) {
  return api<{ ok: boolean }>('/plan/metrics', {
    method: 'PUT',
    body: JSON.stringify(m),
  });
}

export function upsertGoal(g: {
  target_weight: number;
  pace_mode: 'rate' | 'date';
  rate_kg_per_week?: number;
  target_date?: string;
}) {
  return api<{ ok: boolean; goal: WeightGoal }>('/plan/goal', {
    method: 'PUT',
    body: JSON.stringify(g),
  });
}

export function applyBudget() {
  return api<{ ok: boolean; budget: number }>('/plan/goal/apply-budget', {
    method: 'POST',
  });
}

export function abandonGoal() {
  return api<{ ok: boolean }>('/plan/goal/abandon', { method: 'POST' });
}
