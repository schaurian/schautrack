import { describe, it, expect, vi, beforeEach } from 'vitest';

const getMe = vi.hoisted(() => vi.fn());
vi.mock('@/api/auth', () => ({ getMe }));

import { useAuthStore } from './authStore';
import { readSessionHint } from '@/lib/sessionHint';

describe('session hint', () => {
  beforeEach(() => {
    localStorage.clear();
    useAuthStore.setState({ user: null, isInitialized: false, isLoading: true });
    localStorage.clear();
  });

  it('is remembered once /api/me returns a user', async () => {
    getMe.mockResolvedValueOnce({ user: { id: 1, email: 'a@b.c' }, isAdmin: false, pendingLinkRequests: 0 });
    expect(readSessionHint()).toBe(false);
    await useAuthStore.getState().fetchUser();
    expect(readSessionHint()).toBe(true);
  });

  it('is forgotten when the session check finds no user, or the user is cleared', async () => {
    localStorage.setItem('schautrack.signedIn', '1');
    getMe.mockRejectedValueOnce(new Error('401'));
    await useAuthStore.getState().fetchUser();
    expect(readSessionHint()).toBe(false);

    getMe.mockResolvedValueOnce({ user: { id: 1, email: 'a@b.c' }, isAdmin: false, pendingLinkRequests: 0 });
    await useAuthStore.getState().fetchUser();
    expect(readSessionHint()).toBe(true);
    useAuthStore.getState().clearUser();
    expect(readSessionHint()).toBe(false);
  });

  it('is left alone before the first session check', () => {
    localStorage.setItem('schautrack.signedIn', '1');
    useAuthStore.setState({ isLoading: true });
    expect(readSessionHint()).toBe(true);
  });
});
