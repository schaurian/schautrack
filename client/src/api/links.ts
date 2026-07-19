import { api } from './client';
import type { LinkShares } from '@/types';

export function requestLink(email: string) {
  return api<{ ok: boolean; error?: string }>('/settings/link/request', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export function respondToLink(linkId: number, action: 'accept' | 'decline') {
  return api<{ ok: boolean }>('/settings/link/respond', {
    method: 'POST',
    body: JSON.stringify({ request_id: linkId, action }),
  });
}

export function removeLink(linkId: number) {
  return api<{ ok: boolean }>('/settings/link/remove', {
    method: 'POST',
    body: JSON.stringify({ link_id: linkId }),
  });
}

export function updateLinkLabel(linkId: number, label: string) {
  return api<{ ok: boolean }>(`/links/${linkId}/label`, {
    method: 'POST',
    body: JSON.stringify({ label }),
  });
}

export function setLinkShares(linkId: number, shares: LinkShares) {
  return api<{ ok: boolean; shares: LinkShares }>(`/links/${linkId}/shares`, {
    method: 'POST',
    body: JSON.stringify(shares),
  });
}
