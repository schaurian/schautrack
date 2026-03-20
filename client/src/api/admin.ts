import { api } from './client';
import type { AdminData, InviteCode } from '@/types';

export function getAdminData() {
  return api<AdminData>('/api/admin');
}

export function saveAdminSettings(data: Record<string, string>) {
  return api<{ ok: boolean }>('/admin/settings', {
    method: 'POST',
    body: JSON.stringify({ settings: data }),
  });
}

export function deleteUser(userId: number) {
  return api<{ ok: boolean }>(`/admin/users/${userId}/delete`, { method: 'POST' });
}

export function createInvite(data: { email?: string }) {
  return api<{ ok: boolean; invite: InviteCode }>('/admin/invites', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function getInvites() {
  return api<{ ok: boolean; invites: InviteCode[] }>('/admin/invites');
}

export function deleteInvite(id: number) {
  return api<{ ok: boolean }>(`/admin/invites/${id}/delete`, { method: 'POST' });
}
