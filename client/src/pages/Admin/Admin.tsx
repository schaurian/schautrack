import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAdmin } from '@/hooks/useAuth';
import { getAdminData, saveAdminSettings, deleteUser, createInvite, getInvites, deleteInvite } from '@/api/admin';
import { Button } from '@/components/ui/Button';
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

  const isInviteMode = data.settings.registration_mode?.value === 'invite';

  return (
    <div className="flex flex-col gap-6">
      <AdminSettingsForm settings={data.settings} onSave={() => queryClient.invalidateQueries({ queryKey: ['admin'] })} />

      {isInviteMode && <InviteManager />}

      <Card>
        <h3 className="text-base font-semibold mb-4">Users</h3>
        <div className="flex flex-col">
          {data.users.map((user) => (
            <div key={user.id} className="flex items-center gap-3 border-b border-border py-2 text-sm last:border-b-0">
              <span className="flex-1 font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{user.email}</span>
              <span className="text-xs text-muted-foreground whitespace-nowrap">
                {user.email_verified ? 'Verified' : 'Unverified'}
                {' \u00B7 '}
                {new Date(user.created_at).toLocaleDateString()}
              </span>
              <Button size="sm" variant="destructive" onClick={() => handleDeleteUser(user.id)}>Delete</Button>
            </div>
          ))}
        </div>
      </Card>
    </div>
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
      await saveAdminSettings(values);
      onSave();
    } catch { /* ignore */ }
    setLoading(false);
  };

  const settingLabels: Record<string, string> = {
    support_email: 'Support Email',
    imprint_address: 'Imprint Address',
    imprint_email: 'Imprint Email',
    enable_legal: 'Enable Legal Pages',
    ai_provider: 'AI Provider',
    ai_key: 'AI Key',
    ai_endpoint: 'AI Endpoint',
    ai_model: 'AI Model',
    ai_daily_limit: 'AI Daily Limit',
    registration_mode: 'Registration Mode (open/invite)',
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Application Settings</h3>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        {Object.entries(settings).map(([key, setting]) => (
          <div key={key}>
            <Input
              label={`${settingLabels[key] || key} ${setting.source === 'env' ? '(ENV)' : ''}`}
              value={values[key] || ''}
              onChange={(e) => setValues({ ...values, [key]: e.target.value })}
              disabled={setting.source === 'env'}
            />
          </div>
        ))}
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
    } catch { /* ignore */ }
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
