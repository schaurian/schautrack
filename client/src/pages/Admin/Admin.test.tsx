import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdminData, AdminUser, AdminUserSort } from '@/types';
import Admin from './Admin';

// The admin user list shows each account's last login and lets the admin
// order by it. The order is the server's (GET /api/admin?sort=…), so these
// tests pin what the page asks for and that it renders exactly what comes back.

vi.mock('@/hooks/useAuth', () => ({
  useRequireAdmin: () => ({ isLoading: false }),
}));

vi.mock('@/api/admin', () => ({
  getAdminData: vi.fn(),
  getInvites: vi.fn(),
  saveAdminSettings: vi.fn(),
  deleteUser: vi.fn(),
  createInvite: vi.fn(),
  deleteInvite: vi.fn(),
}));

import { getAdminData, getInvites } from '@/api/admin';

const HOUR = 3600 * 1000;
const user = (id: number, email: string, lastLoginAgoHours: number | null): AdminUser => ({
  id,
  email,
  email_verified: true,
  created_at: '2026-01-01T00:00:00Z',
  last_login_at: lastLoginAgoHours === null ? null : new Date(Date.now() - lastLoginAgoHours * HOUR).toISOString(),
});

const alice = user(1, 'alice@example.test', 3 * 24); // 3 days ago
const bob = user(2, 'bob@example.test', 2); // 2 hours ago
const carol = user(3, 'carol@example.test', null); // none recorded

const BY_SORT: Record<AdminUserSort, AdminUser[]> = {
  created: [carol, bob, alice],
  last_login_desc: [bob, alice, carol],
  last_login_asc: [alice, bob, carol],
};

function adminData(users: AdminUser[]): AdminData {
  return { users, settings: {} };
}

function renderAdmin() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Admin />
    </QueryClientProvider>,
  );
}

async function emailsInOrder() {
  const rows = await screen.findAllByTestId('admin-user-row');
  return rows.map((r) => within(r).getByText(/@example\.test$/).textContent);
}

beforeEach(() => {
  vi.mocked(getAdminData).mockReset();
  vi.mocked(getAdminData).mockImplementation(async (sort: AdminUserSort = 'created') => adminData(BY_SORT[sort]));
  vi.mocked(getInvites).mockResolvedValue({ ok: true, invites: [] });
});

describe('Admin user list — last login', () => {
  it('shows a relative last login with the exact time on hover', async () => {
    renderAdmin();
    const row = (await screen.findByText('bob@example.test')).closest('[data-testid="admin-user-row"]') as HTMLElement;
    const cell = within(row).getByTestId('admin-user-last-login');
    expect(cell).toHaveTextContent('Last login 2 hours ago');
    const time = within(cell).getByText('2 hours ago');
    expect(time.tagName).toBe('TIME');
    expect(time).toHaveAttribute('dateTime', bob.last_login_at);
    // The tooltip is the absolute timestamp, not the relative text again.
    expect(time.getAttribute('title')).toMatch(/2026|\d{4}/);
    expect(time.getAttribute('title')).not.toMatch(/ago/);
  });

  it('does not claim "never" for an account with no recorded login', async () => {
    renderAdmin();
    const row = (await screen.findByText('carol@example.test')).closest('[data-testid="admin-user-row"]') as HTMLElement;
    const cell = within(row).getByTestId('admin-user-last-login');
    expect(cell).toHaveAttribute('title', 'No login recorded since this was introduced');
    expect(cell).toHaveTextContent('Last login —');
    expect(cell.textContent).not.toMatch(/never/i);
  });

  // At phone width the last login wraps onto its own line; a "·" glued to the
  // date then dangled at the end of the first line ("Verified · 11/3/2026 ·").
  it('does not end the verified/date part with a separator', async () => {
    renderAdmin();
    const row = (await screen.findByText('bob@example.test')).closest('[data-testid="admin-user-row"]') as HTMLElement;
    const details = within(row).getByText(/^Verified · /);
    expect(details.textContent).not.toMatch(/\u00B7\s*$/);
    // The separator is its own element, shown only where the line does not wrap.
    const sep = within(row).getByTestId('admin-user-last-login-sep');
    expect(sep).toHaveTextContent('\u00B7');
    expect(sep).toHaveAttribute('aria-hidden', 'true');
    expect(sep).toHaveClass('hidden', 'sm:inline');
  });

  it('keeps the default order and asks the server for it', async () => {
    renderAdmin();
    expect(await emailsInOrder()).toEqual(['carol@example.test', 'bob@example.test', 'alice@example.test']);
    expect(getAdminData).toHaveBeenLastCalledWith('created');
    expect(screen.getByRole('radio', { name: 'Newest' })).toHaveAttribute('aria-checked', 'true');
  });

  it('re-queries the server in the chosen order and renders it', async () => {
    const u = userEvent.setup();
    renderAdmin();
    await emailsInOrder();

    await u.click(screen.getByRole('radio', { name: 'Recent login' }));
    expect(getAdminData).toHaveBeenLastCalledWith('last_login_desc');
    await waitFor(async () =>
      expect(await emailsInOrder()).toEqual(['bob@example.test', 'alice@example.test', 'carol@example.test']));

    await u.click(screen.getByRole('radio', { name: 'Oldest login' }));
    expect(getAdminData).toHaveBeenLastCalledWith('last_login_asc');
    await waitFor(async () =>
      expect(await emailsInOrder()).toEqual(['alice@example.test', 'bob@example.test', 'carol@example.test']));
    expect(screen.getByRole('radio', { name: 'Oldest login' })).toHaveAttribute('aria-checked', 'true');
  });
});
