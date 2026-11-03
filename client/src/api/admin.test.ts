import { beforeEach, describe, expect, it, vi } from 'vitest';

// The admin user list is ordered by the server: each sort option must reach
// GET /api/admin as the exact query the handler whitelists
// (adminUsersOrderBy in internal/handler/api.go).

vi.mock('./client', () => ({ api: vi.fn().mockResolvedValue({ users: [], settings: {} }) }));

import { api } from './client';
import { getAdminData } from './admin';

describe('getAdminData', () => {
  beforeEach(() => vi.mocked(api).mockClear());

  it.each([
    [undefined, '/api/admin'],
    ['created', '/api/admin'],
    ['last_login_desc', '/api/admin?sort=last_login&order=desc'],
    ['last_login_asc', '/api/admin?sort=last_login&order=asc'],
  ] as const)('sort %s requests %s', async (sort, url) => {
    await getAdminData(sort);
    expect(api).toHaveBeenCalledWith(url);
  });
});
