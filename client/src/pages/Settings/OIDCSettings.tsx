import { useEffect, useState } from 'react';
import { api } from '@/api/client';
import { getAuthInfo, type AuthInfo } from '@/api/passkeys';
import { useAuthStore } from '@/stores/authStore';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  linked: boolean;
  onUpdate: () => void;
}

export default function OIDCSettings({ linked, onUpdate }: Props) {
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const addToast = useToastStore((s) => s.addToast);
  const fetchUser = useAuthStore((s) => s.fetchUser);

  useEffect(() => {
    getAuthInfo().then(setAuthInfo).catch(() => {});
  }, []);

  if (!authInfo || !authInfo.oidc) return null;
  const oidc = authInfo.oidc;

  const handleLink = () => {
    window.location.href = '/auth/oidc/login';
  };

  const handleUnlink = async () => {
    if (!confirm(`Unlink ${oidc.label}?`)) return;
    try {
      const settingsData = await api<{ oidcAccounts?: { id: number; provider: string }[] }>('/api/settings');
      const account = settingsData.oidcAccounts?.[0];
      if (!account) {
        addToast('error', 'Account not found');
        return;
      }
      await api('/settings/oidc/unlink', {
        method: 'POST',
        body: JSON.stringify({ id: account.id }),
      });
      addToast('success', `${oidc.label} unlinked`);
      fetchUser();
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to unlink');
    }
  };

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">Single Sign-On</h3>
      </div>
      <div className="p-4 flex flex-col gap-2">
        <div className="flex items-center justify-between rounded-lg border border-border px-3 py-2">
          <span className="flex items-center gap-2 text-sm text-foreground">
            {oidc.logo && (
              <img src={oidc.logo} alt="" className="w-5 h-5"
                onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} />
            )}
            {oidc.label}
          </span>
          {linked ? (
            <button
              className="text-xs text-destructive hover:text-destructive/80 cursor-pointer bg-transparent border-0 p-1 transition-colors"
              onClick={handleUnlink}
            >
              Unlink
            </button>
          ) : (
            <button
              className="text-xs text-primary hover:text-primary/80 cursor-pointer bg-transparent border-0 p-1 transition-colors"
              onClick={handleLink}
            >
              Link
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
