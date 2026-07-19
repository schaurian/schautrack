import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAdmin } from '@/hooks/useAuth';
import { getAdminData, saveAdminSettings, deleteUser, createInvite, getInvites, deleteInvite } from '@/api/admin';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import type { InviteCode } from '@/types';

export default function Admin() {
  const { t } = useTranslation('settings');
  const { isLoading: authLoading } = useRequireAdmin();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['admin'], queryFn: getAdminData });

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center p-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const handleDeleteUser = async (userId: number) => {
    if (!confirm(t('admin.deleteUserConfirm'))) return;
    try {
      await deleteUser(userId);
      queryClient.invalidateQueries({ queryKey: ['admin'] });
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('admin.deleteUserFailed'));
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <AdminSettingsForm
        settings={data.settings as unknown as Record<string, SettingMeta>}
        settingsOrder={(data as unknown as { settingsOrder?: string[] }).settingsOrder ?? Object.keys(data.settings)}
        onSave={() => queryClient.invalidateQueries({ queryKey: ['admin'] })}
      />

      <InviteManager />

      <UserList users={data.users} onDelete={handleDeleteUser} />
    </div>
  );
}

const INITIAL_USERS = 25;
const LOAD_MORE_BATCH = 25;

function UserList({ users, onDelete }: { users: Array<{ id: number; email: string; email_verified: boolean; created_at: string }>; onDelete: (id: number) => void }) {
  const { t } = useTranslation('settings');
  const [search, setSearch] = useState('');
  const [shown, setShown] = useState(INITIAL_USERS);
  const sentinelRef = useRef<HTMLDivElement>(null);

  const filtered = search
    ? users.filter((u) => u.email.toLowerCase().includes(search.toLowerCase()))
    : users;
  const visible = filtered.slice(0, shown);
  const hasMore = shown < filtered.length;

  // Infinite scroll: when the bottom sentinel comes into view, reveal another
  // batch. Re-runs when filtered grows/shrinks or shown changes.
  useEffect(() => {
    if (!hasMore) return;
    const node = sentinelRef.current;
    if (!node) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown((n) => n + LOAD_MORE_BATCH);
        }
      },
      { rootMargin: '120px' },
    );
    obs.observe(node);
    return () => obs.disconnect();
  }, [hasMore, filtered.length]);

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold">{t('admin.usersHeading', { count: filtered.length })}</h3>
      </div>
      <input
        type="text"
        value={search}
        onChange={(e) => { setSearch(e.target.value); setShown(INITIAL_USERS); }}
        placeholder={t('admin.searchPlaceholder')}
        className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring mb-3"
      />
      <div className="flex flex-col">
        {visible.map((user) => (
          <div key={user.id} className="flex items-center gap-3 border-b border-border py-2 text-sm last:border-b-0">
            <span className="flex-1 font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{user.email}</span>
            <span className="text-xs text-muted-foreground whitespace-nowrap">
              {user.email_verified ? t('admin.verified') : t('admin.unverified')}
              {' \u00B7 '}
              {new Date(user.created_at).toLocaleDateString()}
            </span>
            <Button size="sm" variant="destructive" onClick={() => onDelete(user.id)}>{t('admin.delete')}</Button>
          </div>
        ))}
        {visible.length === 0 && (
          <div className="py-4 text-center text-sm text-muted-foreground">{t('admin.noUsersFound')}</div>
        )}
      </div>
      {hasMore && (
        <div ref={sentinelRef} className="py-3 text-center text-xs text-muted-foreground">
          {t('admin.loadingMore')}
        </div>
      )}
    </Card>
  );
}

interface SettingMeta {
  value: string;
  source: string;
  section: string;
  tier: 'hot' | 'restart';
  secret: boolean;
  dangerous: boolean;
  help: string;
  isSet: boolean;
  envVar: string;
}

// Order in which sections are rendered; titles/descriptions come from the
// `admin.sections.<key>` i18n catalog.
const SECTION_ORDER = ['general', 'ai', 'oidc', 'passkeys', 'features', 'smtp', 'security', 'legal', 'seo'];

function AdminSettingsForm({
  settings,
  settingsOrder,
  onSave,
}: {
  settings: Record<string, SettingMeta>;
  settingsOrder: string[];
  onSave: () => void;
}) {
  const { t } = useTranslation('settings');
  // values are user-edited drafts; only keys present here are sent on save.
  // Secret fields default to absent (we never receive the stored value); a
  // user typing into one populates the draft.
  const [values, setValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);

  // Group settings by section, preserving the canonical order from the server.
  const sections: Record<string, string[]> = {};
  for (const key of settingsOrder) {
    const s = settings[key];
    if (!s) continue;
    (sections[s.section] ??= []).push(key);
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Confirm dangerous changes.
    const dangerousChanges = Object.keys(values).filter((k) => settings[k]?.dangerous);
    for (const k of dangerousChanges) {
      const meta = settings[k];
      const phrase = k === 'passkeys_rp_id' ? t('admin.confirmPhraseInvalidatePasskeys')
        : k === 'ai_key_encryption_secret' ? t('admin.confirmPhraseOrphanAiKeys')
        : t('admin.confirmPhraseGeneric');
      const typed = window.prompt(
        t('admin.dangerousPrompt', { envVar: meta.envVar, help: meta.help, phrase }),
      );
      if (typed !== phrase) {
        useToastStore.getState().addToast('info', t('admin.saveCancelled'));
        return;
      }
    }

    setLoading(true);
    try {
      // Only send settings that aren't env-controlled.
      const editable = Object.fromEntries(
        Object.entries(values).filter(([k]) => settings[k]?.source !== 'env'),
      );
      if (Object.keys(editable).length === 0) {
        useToastStore.getState().addToast('info', t('admin.noChanges'));
        setLoading(false);
        return;
      }
      await saveAdminSettings(editable);
      setValues({});
      onSave();
      useToastStore.getState().addToast('success', t('admin.settingsSaved'));
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('admin.saveSettingsFailed'));
    }
    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">{t('admin.appSettingsHeading')}</h2>
      {SECTION_ORDER.map((sectionKey) => {
        const keys = sections[sectionKey];
        if (!keys || keys.length === 0) return null;
        const title = t(`admin.sections.${sectionKey}.title`);
        const description = t(`admin.sections.${sectionKey}.description`, { defaultValue: '' }) || undefined;
        return (
          <SettingsSection
            key={sectionKey}
            title={title}
            description={description}
            keys={keys}
            settings={settings}
            values={values}
            setValues={setValues}
          />
        );
      })}
      <div className="flex justify-end">
        <Button type="submit" loading={loading}>{t('admin.save')}</Button>
      </div>
    </form>
  );
}

function SettingsSection({
  title,
  description,
  keys,
  settings,
  values,
  setValues,
}: {
  title: string;
  description?: string;
  keys: string[];
  settings: Record<string, SettingMeta>;
  values: Record<string, string>;
  setValues: (next: Record<string, string>) => void;
}) {
  return (
    <Card>
      <h3 className="text-base font-semibold mb-1">{title}</h3>
      {description && <p className="text-xs text-muted-foreground mb-4">{description}</p>}
      <div className="flex flex-col gap-3">
        {keys.map((key) => (
          <SettingField
            key={key}
            settingKey={key}
            meta={settings[key]}
            draft={values[key]}
            isDirty={key in values}
            onChange={(v) => setValues({ ...values, [key]: v })}
          />
        ))}
      </div>
    </Card>
  );
}

function SettingField({
  settingKey,
  meta,
  draft,
  isDirty,
  onChange,
}: {
  settingKey: string;
  meta: SettingMeta;
  draft: string | undefined;
  isDirty: boolean;
  onChange: (v: string) => void;
}) {
  const { t } = useTranslation('settings');
  const [revealing, setRevealing] = useState(false);
  const isEnv = meta.source === 'env';
  const isBool = ['enable_legal', 'enable_barcode', 'oidc_require_invite', 'smtp_secure', 'trust_proxy', 'robots_index'].includes(settingKey);
  const isRegistrationMode = settingKey === 'enable_registration';
  const value = isDirty ? draft! : meta.value;

  // Secrets: don't pre-populate the input. Show a "set" indicator + Replace
  // button. Once revealing, show an empty input the user types into.
  const showSecretMask = meta.secret && !isDirty && !revealing;

  const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed';

  const fieldId = `admin-setting-${settingKey}`;
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2 flex-wrap">
        <label htmlFor={fieldId} className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {meta.envVar}
        </label>
        {isEnv && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">
            {t('admin.envBadge')}
          </span>
        )}
        {meta.tier === 'restart' && !isEnv && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30" title={t('admin.restartRequiredTitle')}>
            {t('admin.restartRequiredBadge')}
          </span>
        )}
        {meta.dangerous && !isEnv && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/30">
            {t('admin.dangerousBadge')}
          </span>
        )}
        {isDirty && <span className="text-[10px] text-primary">{t('admin.unsavedBadge')}</span>}
      </div>

      {isRegistrationMode ? (
        <select
          id={fieldId}
          className={inputClass}
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          disabled={isEnv}
        >
          <option value="">{t('admin.registrationDefault')}</option>
          <option value="open">{t('admin.registrationOpen')}</option>
          <option value="invite">{t('admin.registrationInvite')}</option>
          <option value="false">{t('admin.registrationDisabled')}</option>
        </select>
      ) : isBool ? (
        <select
          id={fieldId}
          className={inputClass}
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          disabled={isEnv}
        >
          <option value="">{t('admin.unset')}</option>
          <option value="true">{t('admin.boolTrue')}</option>
          <option value="false">{t('admin.boolFalse')}</option>
        </select>
      ) : showSecretMask ? (
        <div className="flex items-center gap-2">
          <span className={`flex-1 ${inputClass} ${meta.isSet ? 'text-muted-foreground' : 'text-muted-foreground/50'}`}>
            {meta.isSet ? t('admin.secretStored') : t('admin.unset')}
          </span>
          <Button type="button" size="sm" variant="ghost" onClick={() => setRevealing(true)} disabled={isEnv}>
            {t('admin.replace')}
          </Button>
        </div>
      ) : (
        <input
          id={fieldId}
          type={meta.secret ? 'password' : 'text'}
          className={inputClass}
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          disabled={isEnv}
          placeholder={meta.secret ? t('admin.secretPlaceholder') : ''}
          autoComplete={meta.secret ? 'new-password' : 'off'}
        />
      )}

      {meta.help && <p className="text-xs text-muted-foreground/80">{meta.help}</p>}
    </div>
  );
}

function InviteManager() {
  const { t } = useTranslation('settings');
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
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('admin.createInviteFailed'));
    }
    setCreating(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteInvite(id);
      queryClient.invalidateQueries({ queryKey: ['invites'] });
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('admin.deleteInviteFailed'));
    }
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
      <h3 className="text-base font-semibold mb-4">{t('admin.inviteCodesHeading')}</h3>
      <form onSubmit={handleCreate} className="flex gap-2 mb-4">
        <Input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={t('admin.emailOptionalPlaceholder')}
          className="flex-1"
        />
        <Button type="submit" size="sm" loading={creating}>{t('admin.createInvite')}</Button>
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
                    {t('admin.expiresOn', { date: new Date(invite.expires_at).toLocaleDateString() })}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {invite.used_by ? (
                  <span className="text-xs text-muted-foreground">{t('admin.usedBy', { email: invite.used_by_email })}</span>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={() => handleCopy(invite)}
                      className="text-xs text-primary hover:underline"
                    >
                      {copiedId === invite.id ? t('admin.copied') : t('admin.copyLink')}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(invite.id)}
                      className="text-xs text-muted-foreground hover:text-destructive transition-colors"
                    >
                      {t('admin.delete')}
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
