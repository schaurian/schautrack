import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAdmin } from '@/hooks/useAuth';
import { getAdminData, saveAdminSettings, deleteUser, createInvite, getInvites, deleteInvite } from '@/api/admin';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import type { InviteCode } from '@/types';

export default function Admin() {
  const { isLoading: authLoading } = useRequireAdmin();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['admin'], queryFn: getAdminData });

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center p-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const handleDeleteUser = async (userId: number) => {
    if (!confirm('Delete this user?')) return;
    await deleteUser(userId);
    queryClient.invalidateQueries({ queryKey: ['admin'] });
  };

  return (
    <div className="flex flex-col gap-6">
      <AdminSettingsForm settings={data.settings} onSave={() => queryClient.invalidateQueries({ queryKey: ['admin'] })} />

      <InviteManager />

      <UserList users={data.users} onDelete={handleDeleteUser} />
    </div>
  );
}

const PAGE_SIZE = 100;

function UserList({ users, onDelete }: { users: Array<{ id: number; email: string; email_verified: boolean; created_at: string }>; onDelete: (id: number) => void }) {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);

  const filtered = search
    ? users.filter((u) => u.email.toLowerCase().includes(search.toLowerCase()))
    : users;

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold">Users ({filtered.length})</h3>
      </div>
      <input
        type="text"
        value={search}
        onChange={(e) => { setSearch(e.target.value); setPage(0); }}
        placeholder="Search by email..."
        className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring mb-3"
      />
      <div className="flex flex-col">
        {paged.map((user) => (
          <div key={user.id} className="flex items-center gap-3 border-b border-border py-2 text-sm last:border-b-0">
            <span className="flex-1 font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{user.email}</span>
            <span className="text-xs text-muted-foreground whitespace-nowrap">
              {user.email_verified ? 'Verified' : 'Unverified'}
              {' \u00B7 '}
              {new Date(user.created_at).toLocaleDateString()}
            </span>
            <Button size="sm" variant="destructive" onClick={() => onDelete(user.id)}>Delete</Button>
          </div>
        ))}
        {paged.length === 0 && (
          <div className="py-4 text-center text-sm text-muted-foreground">No users found</div>
        )}
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
          <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button>
          <span className="text-xs text-muted-foreground">{page + 1} / {totalPages}</span>
          <Button size="sm" variant="ghost" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>Next</Button>
        </div>
      )}
    </Card>
  );
}

function AdminSettingsForm({ settings, onSave }: { settings: Record<string, { value: string; source: string }>; onSave: () => void }) {
  const [values, setValues] = useState<Record<string, string>>(
    Object.fromEntries(Object.entries(settings).map(([k, v]) => [k, v.value]))
  );
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      // Only send settings that are NOT env-controlled (env-controlled ones are rejected by backend)
      const editableValues = Object.fromEntries(
        Object.entries(values).filter(([k]) => settings[k]?.source !== 'env')
      );
      await saveAdminSettings(editableValues);
      onSave();
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : 'Failed to save settings');
    }
    setLoading(false);
  };

  const settingLabels: Record<string, string> = {
    support_email: 'SUPPORT_EMAIL',
    imprint_address: 'IMPRINT_ADDRESS',
    imprint_email: 'IMPRINT_EMAIL',
    enable_legal: 'ENABLE_LEGAL',
    ai_provider: 'AI_PROVIDER',
    ai_key: 'AI_KEY',
    ai_endpoint: 'AI_ENDPOINT',
    ai_model: 'AI_MODEL',
    ai_daily_limit: 'AI_DAILY_LIMIT',
    enable_registration: 'ENABLE_REGISTRATION',
    enable_barcode: 'ENABLE_BARCODE',
  };

  const toggleSettings: Record<string, { trueValue: string; falseValue: string; defaultValue: string }> = {
    enable_registration: { trueValue: 'true', falseValue: 'false', defaultValue: 'true' },
    enable_barcode: { trueValue: 'true', falseValue: 'false', defaultValue: 'true' },
  };

  const selectClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed';

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Application Settings</h3>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        {Object.entries(settings).map(([key, setting]) => {
          const isEnv = setting.source === 'env';
          const label = settingLabels[key] || key;
          const toggle = toggleSettings[key];

          const envTitle = isEnv ? 'Locked — set via environment variable' : undefined;

          if (toggle) {
            const effectiveValue = values[key] || toggle.defaultValue;
            const isOn = effectiveValue === toggle.trueValue;
            return (
              <div key={key} className="flex flex-col gap-1.5" title={envTitle}>
                <label className="text-xs font-medium text-muted-foreground">{label}</label>
                <select
                  className={selectClass}
                  value={isOn ? 'true' : 'false'}
                  onChange={(e) => setValues({ ...values, [key]: e.target.value === 'true' ? toggle.trueValue : toggle.falseValue })}
                  disabled={isEnv}
                >
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
            );
          }

          return (
            <div key={key} title={envTitle}>
              <Input
                label={label}
                value={values[key] || ''}
                onChange={(e) => setValues({ ...values, [key]: e.target.value })}
                disabled={isEnv}
              />
            </div>
          );
        })}
        <Button type="submit" size="sm" loading={loading}>Save</Button>
      </form>
    </Card>
  );
}

function InviteManager() {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['invites'], queryFn: getInvites });
  const [email, setEmail] = useState('');
  const [creating, setCreating] = useState(false);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      await createInvite({ email: email || undefined });
      setEmail('');
      queryClient.invalidateQueries({ queryKey: ['invites'] });
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : 'Failed to create invite');
    }
    setCreating(false);
  };

  const handleDelete = async (id: number) => {
    await deleteInvite(id);
    queryClient.invalidateQueries({ queryKey: ['invites'] });
  };

  const handleCopy = async (invite: InviteCode) => {
    const link = `${window.location.origin}/register?invite=${invite.code}`;
    try {
      await navigator.clipboard.writeText(link);
      setCopiedId(invite.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch { /* ignore */ }
  };

  const invites = data?.invites || [];

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Invite Codes</h3>
      <form onSubmit={handleCreate} className="flex gap-2 mb-4">
        <Input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email (optional)"
          className="flex-1"
        />
        <Button type="submit" size="sm" loading={creating}>Create Invite</Button>
      </form>

      {invites.length > 0 && (
        <div className="flex flex-col divide-y divide-border rounded-md border border-border overflow-hidden">
          {invites.map((invite) => (
            <div key={invite.id} className="flex items-center gap-3 px-3 py-2 text-sm">
              <div className="flex-1 min-w-0">
                <code className="text-xs font-mono text-foreground break-all">{invite.code}</code>
                {invite.email && <span className="text-xs text-muted-foreground ml-2">{invite.email}</span>}
                {invite.expires_at && !invite.used_by && (
                  <span className={`text-xs ml-2 ${new Date(invite.expires_at) < new Date() ? 'text-destructive' : 'text-muted-foreground/60'}`}>
                    expires {new Date(invite.expires_at).toLocaleDateString()}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {invite.used_by ? (
                  <span className="text-xs text-muted-foreground">Used by {invite.used_by_email}</span>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={() => handleCopy(invite)}
                      className="text-xs text-primary hover:underline"
                    >
                      {copiedId === invite.id ? 'Copied!' : 'Copy Link'}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(invite.id)}
                      className="text-xs text-muted-foreground hover:text-destructive transition-colors"
                    >
                      Delete
                    </button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
