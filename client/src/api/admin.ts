import { api } from './client';
import type { AdminData, AdminUserSort, InviteCode } from '@/types';

const SORT_QUERY: Record<AdminUserSort, string> = {
  created: '',
  last_login_desc: '?sort=last_login&order=desc',
  last_login_asc: '?sort=last_login&order=asc',
};

export function getAdminData(sort: AdminUserSort = 'created') {
  return api<AdminData>(`/api/admin${SORT_QUERY[sort]}`);
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
