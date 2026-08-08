import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  listApiTokens,
  createApiToken,
  revokeApiToken,
  type ApiToken,
  type ScopeInfo,
} from '@/api/apiTokens';
import { Button } from '@/components/ui/Button';
import { isAtTokenLimit, isTokenExpired } from '@/lib/apiTokenLimits';
import { useToastStore } from '@/stores/toastStore';

/**
 * Personal access tokens for the public API (/api/v1).
 *
 * Lives on /account with the other credentials, not on /settings: a token is a
 * way to authenticate as this account, not a tracking preference.
 *
 * The created secret is held in component state and shown once. It is
 * deliberately NOT persisted anywhere — not localStorage, not the query cache —
 * because the whole security property of hashing it server-side is that no
 * second copy exists.
 */
export default function ApiTokenSettings() {
  const { t } = useTranslation('settings');
  const addToast = useToastStore((s) => s.addToast);

  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [scopes, setScopes] = useState<ScopeInfo[]>([]);
  const [max, setMax] = useState(20);
  const [loaded, setLoaded] = useState(false);

  const [creating, setCreating] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [name, setName] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [expiry, setExpiry] = useState<string>('90');

  // The one-time secret. Cleared when the user dismisses it.
  const [freshToken, setFreshToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const data = await listApiTokens();
      setTokens(data.tokens || []);
      setScopes(data.scopes || []);
      setMax(data.max || 20);
    } catch {
      /* The card simply stays empty; the page has other content. */
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const toggleScope = (scope: string) => {
    setSelected((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  };

  const resetForm = () => {
    setFormOpen(false);
    setName('');
    setSelected([]);
    setExpiry('90');
  };

  const handleCreate = async () => {
    if (!name.trim() || selected.length === 0) return;
    setCreating(true);
    try {
      const days = expiry === 'never' ? undefined : Number(expiry);
      const res = await createApiToken(name.trim(), selected, days);
      setFreshToken(res.token);
      setCopied(false);
      resetForm();
      refresh();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('apiTokens.createFailed'));
    }
    setCreating(false);
  };

  const handleRevoke = async (token: ApiToken) => {
    try {
      await revokeApiToken(token.id);
      setTokens((prev) => prev.filter((x) => x.id !== token.id));
      addToast('success', t('apiTokens.revoked', { name: token.name }));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('apiTokens.revokeFailed'));
    }
  };

  const handleCopy = async () => {
    if (!freshToken) return;
    try {
      await navigator.clipboard.writeText(freshToken);
      setCopied(true);
    } catch {
      // Clipboard access can be denied; the value is selectable on screen, so
      // this is a convenience failing, not the flow failing.
      addToast('error', t('apiTokens.copyFailed'));
    }
  };

  if (!loaded) return null;

  // Only live tokens count, exactly as the server's cap does. Gating on
  // tokens.length instead hid the "New token" button from anyone whose expired
  // tokens padded the list to `max`, for tokens the server would have minted.
  const atLimit = isAtTokenLimit(tokens, max);
  const fmtDate = (iso: string) => new Date(iso).toLocaleDateString();

  return (
    <div className="surface overflow-hidden">
      <div className="px-4 pt-4 pb-1">
        <h3 className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">
          {t('apiTokens.heading')}
        </h3>
      </div>

      <div className="p-4 pt-1 flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">
          {t('apiTokens.intro')}{' '}
          <a
            href="/api/v1/docs"
            target="_blank"
            rel="noreferrer"
            className="text-primary hover:underline"
          >
            {t('apiTokens.specLink')}
          </a>
        </p>

        {/* One-time secret display. */}
        {freshToken && (
          <div className="rounded-md border border-primary/40 bg-primary/5 p-3 flex flex-col gap-2">
            <p className="text-sm font-medium text-foreground">{t('apiTokens.copyNow')}</p>
            {/* Distinguishable from the `stk_abc123…` prefix chips in the list
                below, which would otherwise be ambiguous to select. */}
            <code
              data-testid="api-token-secret"
              className="block w-full break-all rounded bg-muted/60 px-2 py-2 text-xs text-foreground select-all"
            >
              {freshToken}
            </code>
            <div className="flex gap-2">
              <Button size="sm" onClick={handleCopy}>
                {copied ? t('apiTokens.copied') : t('apiTokens.copy')}
              </Button>
              <button
                className="text-xs text-muted-foreground hover:text-foreground cursor-pointer bg-transparent border-0 px-2 transition-colors"
                onClick={() => setFreshToken(null)}
              >
                {t('apiTokens.dismiss')}
              </button>
            </div>
          </div>
        )}

        {tokens.length === 0 && !formOpen && (
          <p className="text-sm text-muted-foreground">{t('apiTokens.empty')}</p>
        )}

        {tokens.length > 0 && (
          <div className="flex flex-col divide-y divide-divider">
            {tokens.map((tok) => {
              // An expired token authenticates nothing, so it has to read as
              // dead: greyed name, an "expired" badge, and the date in the
              // destructive colour rather than the same neutral grey a live
              // token's expiry uses.
              const expired = isTokenExpired(tok);
              return (
                <div key={tok.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2.5">
                  <div className="flex-1 min-w-0">
                    <div
                      className={`truncate text-sm ${expired ? 'text-muted-foreground' : 'text-foreground'}`}
                    >
                      {tok.name}
                      {expired && (
                        <span className="ml-2 rounded border border-destructive/40 px-1.5 py-0.5 align-middle text-[10px] font-medium uppercase tracking-wide text-destructive">
                          {t('apiTokens.expiredBadge')}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <code>{tok.prefix}…</code>
                      {' · '}
                      {tok.scopes.join(', ')}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground whitespace-nowrap ml-auto">
                    {tok.last_used_at
                      ? t('apiTokens.usedOn', { date: fmtDate(tok.last_used_at) })
                      : t('apiTokens.neverUsed')}
                    {tok.expires_at && ' · '}
                    {tok.expires_at &&
                      (expired ? (
                        <span className="text-destructive">
                          {t('apiTokens.expiredOn', { date: fmtDate(tok.expires_at) })}
                        </span>
                      ) : (
                        t('apiTokens.expires', { date: fmtDate(tok.expires_at) })
                      ))}
                  </span>
                  <button
                    className="text-xs text-destructive hover:text-destructive/80 cursor-pointer bg-transparent border-0 p-1 transition-colors"
                    onClick={() => handleRevoke(tok)}
                  >
                    {t('apiTokens.revoke')}
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {!formOpen && !atLimit && (
          <Button size="default" onClick={() => setFormOpen(true)} className="w-full">
            {t('apiTokens.newToken')}
          </Button>
        )}

        {atLimit && !formOpen && (
          <p className="text-xs text-muted-foreground">{t('apiTokens.atLimit', { max })}</p>
        )}

        {formOpen && (
          <div className="flex flex-col gap-3 rounded-md border border-input p-3">
            <input
              className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none focus:border-ring placeholder:text-muted-foreground/50"
              placeholder={t('apiTokens.namePlaceholder')}
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={60}
              autoFocus
            />

            <div className="flex flex-col gap-1.5">
              <span className="text-xs font-medium text-muted-foreground">
                {t('apiTokens.scopesLabel')}
              </span>
              {scopes.map((s) => (
                <label key={s.scope} className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-0.5 accent-primary"
                    checked={selected.includes(s.scope)}
                    onChange={() => toggleScope(s.scope)}
                  />
                  <span className="text-sm text-foreground">
                    <code className="text-xs">{s.scope}</code>
                    <span className="block text-xs text-muted-foreground">{s.description}</span>
                  </span>
                </label>
              ))}
            </div>

            <label className="flex flex-col gap-1">
              <span className="text-xs font-medium text-muted-foreground">
                {t('apiTokens.expiryLabel')}
              </span>
              <select
                className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none focus:border-ring"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
              >
                <option value="30">{t('apiTokens.expiry30')}</option>
                <option value="90">{t('apiTokens.expiry90')}</option>
                <option value="365">{t('apiTokens.expiry365')}</option>
                <option value="never">{t('apiTokens.expiryNever')}</option>
              </select>
            </label>

            <div className="flex gap-2">
              <Button
                size="default"
                loading={creating}
                disabled={!name.trim() || selected.length === 0}
                onClick={handleCreate}
                className="flex-1"
              >
                {t('apiTokens.create')}
              </Button>
              <button
                className="text-sm text-muted-foreground hover:text-foreground cursor-pointer bg-transparent border-0 px-3 transition-colors"
                onClick={resetForm}
              >
                {t('apiTokens.cancel')}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
