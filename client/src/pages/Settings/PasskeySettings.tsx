import { useState, useEffect } from 'react';
import { listPasskeys, deletePasskey, renamePasskey, passkeyRegisterBegin, passkeyRegisterFinish, getAuthInfo, type Passkey, type AuthInfo } from '@/api/passkeys';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';
import { startRegistration } from '@simplewebauthn/browser';

interface Props {
  onUpdate: () => void;
}

export default function PasskeySettings({ onUpdate }: Props) {
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
    const name = newName.trim() || 'Passkey';
    setRegistering(true);
    try {
      const options = await passkeyRegisterBegin();
      const credential = await startRegistration({ optionsJSON: options as any });
      await passkeyRegisterFinish(credential as any, name);
      addToast('success', 'Passkey registered');
      setNewName('');
      refresh();
      fetchUser();
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Passkey registration failed');
    }
    setRegistering(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deletePasskey(id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      addToast('success', 'Passkey removed');
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to remove passkey');
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
      addToast('error', err instanceof Error ? err.message : 'Failed to rename');
    }
  };

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">Passkeys</h3>
      </div>
      <div className="p-4 flex flex-col gap-3">
        {passkeys.length === 0 && (
          <p className="text-sm text-muted-foreground">No passkeys registered. Add one for passwordless login.</p>
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
                title="Click to rename"
              >
                {pk.name}
              </button>
            )}
            <span className="text-xs text-muted-foreground whitespace-nowrap ml-auto">
              {pk.lastUsedAt ? `Used ${new Date(pk.lastUsedAt).toLocaleDateString()}` : 'Never used'}
            </span>
            <button
              className="text-xs text-destructive hover:text-destructive/80 cursor-pointer bg-transparent border-0 p-1 transition-colors"
              onClick={() => handleDelete(pk.id)}
            >
              Remove
            </button>
          </div>
        ))}

        {passkeys.length < 10 && (
          <div className="flex flex-col gap-2 mt-1">
            <input
              className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none focus:border-ring placeholder:text-muted-foreground/50"
              placeholder="Passkey name (e.g., Phone, Laptop)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={50}
            />
            <Button size="default" loading={registering} disabled={!newName.trim()} onClick={handleRegister} className="w-full">
              Add Passkey
            </Button>
          </div>
        )}

        {passkeys.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {passkeys.length} of 10 passkeys used.
          </p>
        )}
      </div>
    </div>
  );
}
