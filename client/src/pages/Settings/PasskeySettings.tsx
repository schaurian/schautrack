import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { listPasskeys, deletePasskey, renamePasskey, passkeyRegisterBegin, passkeyRegisterFinish, getAuthInfo, type Passkey, type AuthInfo } from '@/api/passkeys';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';
import { startRegistration } from '@simplewebauthn/browser';

interface Props {
  onUpdate: () => void;
}

export default function PasskeySettings({ onUpdate }: Props) {
  const { t } = useTranslation('settings');
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [newName, setNewName] = useState('');
  const [registering, setRegistering] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editName, setEditName] = useState('');
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const addToast = useToastStore((s) => s.addToast);
  const fetchUser = useAuthStore((s) => s.fetchUser);

  const refresh = async () => {
    try {
      const data = await listPasskeys();
      setPasskeys(data.passkeys || []);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    getAuthInfo().then(setAuthInfo).catch(() => {});
  }, []);

  useEffect(() => {
    if (authInfo?.passkeysEnabled) refresh();
  }, [authInfo?.passkeysEnabled]);

  if (!authInfo) return null;
  if (!authInfo.passkeysEnabled) return null;

  const handleRegister = async () => {
    const name = newName.trim() || t('passkey.defaultName');
    setRegistering(true);
    try {
      const options = await passkeyRegisterBegin();
      const credential = await startRegistration({ optionsJSON: options as any });
      await passkeyRegisterFinish(credential as any, name);
      addToast('success', t('passkey.registered'));
      setNewName('');
      refresh();
      fetchUser();
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('passkey.registerFailed'));
    }
    setRegistering(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deletePasskey(id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      addToast('success', t('passkey.removed'));
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('passkey.removeFailed'));
    }
  };

  const handleRename = async (id: number) => {
    const name = editName.trim();
    if (!name) return;
    try {
      await renamePasskey(id, name);
      setEditingId(null);
      refresh();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('passkey.renameFailed'));
    }
  };

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">{t('passkey.heading')}</h3>
      </div>
      <div className="p-4 flex flex-col gap-3">
        {passkeys.length === 0 && (
          <p className="text-sm text-muted-foreground">{t('passkey.empty')}</p>
        )}

        {passkeys.map((pk) => (
          <div key={pk.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-border px-3 py-2">
            {editingId === pk.id ? (
              <input
                className="flex-1 min-w-0 rounded-md border border-input bg-muted/50 px-2 py-1 text-sm text-foreground outline-none focus:border-ring"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRename(pk.id)}
                onBlur={() => handleRename(pk.id)}
                autoFocus
                maxLength={50}
              />
            ) : (
              <button
                className="flex-1 min-w-0 truncate text-left text-sm text-foreground cursor-pointer bg-transparent border-0 p-0 hover:text-primary transition-colors"
                onClick={() => { setEditingId(pk.id); setEditName(pk.name); }}
                title={t('passkey.renameTitle')}
              >
                {pk.name}
              </button>
            )}
            <span className="text-xs text-muted-foreground whitespace-nowrap ml-auto">
              {pk.lastUsedAt ? t('passkey.usedOn', { date: new Date(pk.lastUsedAt).toLocaleDateString() }) : t('passkey.neverUsed')}
            </span>
            <button
              className="text-xs text-destructive hover:text-destructive/80 cursor-pointer bg-transparent border-0 p-1 transition-colors"
              onClick={() => handleDelete(pk.id)}
            >
              {t('passkey.remove')}
            </button>
          </div>
        ))}

        {passkeys.length < 10 && (
          <div className="flex flex-col gap-2 mt-1">
            <input
              className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none focus:border-ring placeholder:text-muted-foreground/50"
              placeholder={t('passkey.namePlaceholder')}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={50}
            />
            <Button size="default" loading={registering} disabled={!newName.trim()} onClick={handleRegister} className="w-full">
              {t('passkey.add')}
            </Button>
          </div>
        )}

        {passkeys.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {t('passkey.countUsed', { count: passkeys.length })}
          </p>
        )}
      </div>
    </div>
  );
}
