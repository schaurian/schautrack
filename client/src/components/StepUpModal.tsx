import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import * as Dialog from '@radix-ui/react-dialog';
import { startAuthentication } from '@simplewebauthn/browser';
import { useStepUpStore } from '@/stores/stepUpStore';
import { useAuthStore } from '@/stores/authStore';
import { stepUpPasswordTOTP, stepUpPasskeyBegin, stepUpPasskeyFinish } from '@/api/stepup';
import { getAuthInfo, type AuthInfo } from '@/api/passkeys';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Alert } from '@/components/ui/Alert';

// StepUpModal is mounted globally and listens to the step-up store. When a
// gated API call returns 403/requireStepUp, the API client enqueues here and
// suspends the original request; the modal re-authenticates the session and
// then calls pending.retry(), which resolves the original promise.
//
// Built on Radix Dialog because it sets aria-hidden on every sibling of the
// portal'd content while open. That's what makes password managers (Bitwarden,
// 1Password, browser autofill) ignore the page underneath and target the
// modal's password field instead — a hand-rolled overlay with z-index alone
// leaves the background DOM scannable, so autofill targets the wrong input.
export default function StepUpModal() {
  const { t } = useTranslation('common');
  const pending = useStepUpStore((s) => s.pending);
  const clear = useStepUpStore((s) => s.clear);
  const userEmail = useAuthStore((s) => s.user?.email);

  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState<'password' | 'passkey' | 'oidc' | null>(null);
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);

  // Reset form when the modal opens for a new request.
  useEffect(() => {
    if (pending) {
      setPassword('');
      setToken('');
      setError('');
      setLoading(null);
      // Fetch OIDC label/logo so we can render a labeled "Continue with X"
      // button when oidc is in the methods list. Only fires the first time
      // the modal opens — cached after.
      if (!authInfo) getAuthInfo().then(setAuthInfo).catch(() => {});
    }
  }, [pending, authInfo]);

  const cancel = () => {
    pending?.cancel();
    clear();
  };

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pending) return;
    setError('');
    setLoading('password');
    try {
      await stepUpPasswordTOTP(password, token || undefined);
      await pending.retry();
      clear();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('stepUp.errors.stepUpFailed'));
      setLoading(null);
    }
  };

  const submitPasskey = async () => {
    if (!pending) return;
    setError('');
    setLoading('passkey');
    try {
      const opts = await stepUpPasskeyBegin();
      // SimpleWebAuthn types this strictly; the runtime payload is fine.
      const credential = await startAuthentication({ optionsJSON: opts as never });
      await stepUpPasskeyFinish(credential as unknown as Record<string, unknown>);
      await pending.retry();
      clear();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : t('stepUp.errors.passkeyFailed'));
      setLoading(null);
    }
  };

  const startOIDCStepUp = () => {
    setLoading('oidc');
    // Full-page redirect — JavaScript memory (including the suspended
    // request) is lost, but the user lands back here with a fresh step-up
    // grace and can retry the action. The Settings page surfaces a toast
    // from ?success=stepped_up so they know what happened.
    const next = window.location.pathname + window.location.search;
    window.location.href = `/auth/oidc/step-up?next=${encodeURIComponent(next)}`;
  };

  const hasPassword = pending?.methods.includes('password') ?? false;
  const hasPasskey = pending?.methods.includes('passkey') ?? false;
  const hasOIDC = pending?.methods.includes('oidc') ?? false;
  const noMethods = !!pending && !hasPassword && !hasPasskey && !hasOIDC;

  return (
    <Dialog.Root open={!!pending} onOpenChange={(open) => { if (!open) cancel(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-card p-6 text-card-foreground shadow-lg focus:outline-none"
        >
          <Dialog.Title className="text-base font-semibold mb-1">{t('stepUp.title')}</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-4">
            {t('stepUp.description')}
          </Dialog.Description>

          {error && <Alert type="error" message={error} className="mb-4" />}

          {noMethods && (
            <Alert
              type="error"
              message={t('stepUp.noMethods')}
              className="mb-4"
            />
          )}

          {hasPasskey && (
            <Button
              variant="outline"
              className="w-full"
              onClick={submitPasskey}
              loading={loading === 'passkey'}
              disabled={loading !== null}
            >
              {t('stepUp.usePasskey')}
            </Button>
          )}

          {hasOIDC && authInfo?.oidc && (
            <Button
              variant="outline"
              className={hasPasskey ? 'w-full mt-2' : 'w-full'}
              onClick={startOIDCStepUp}
              loading={loading === 'oidc'}
              disabled={loading !== null}
            >
              {authInfo.oidc.logo && (
                <img src={authInfo.oidc.logo} alt="" className="inline-block w-5 h-5 mr-2 align-middle"
                  onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} />
              )}
              {t('stepUp.continueWith', { provider: authInfo.oidc.label })}
            </Button>
          )}

          {hasPassword && (hasPasskey || hasOIDC) && (
            <div className="relative my-3">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
              <div className="relative flex justify-center text-xs">
                <span className="bg-card px-2 text-muted-foreground">{t('stepUp.or')}</span>
              </div>
            </div>
          )}

          {hasPassword && (
            <form onSubmit={submitPassword} className="flex flex-col gap-3">
              {/*
                Hidden username input — Bitwarden, 1Password and the browser's
                built-in password manager all need a username field paired with
                the password to match a stored credential. Without it, autofill
                is silently skipped on this modal.
              */}
              <input
                type="email"
                name="username"
                value={userEmail ?? ''}
                autoComplete="username"
                readOnly
                hidden
              />
              <Input
                label={t('stepUp.password')}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                autoFocus
              />
              {pending?.totpRequired && (
                <Input
                  label={t('stepUp.totpLabel')}
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  inputMode="numeric"
                  maxLength={8}
                  placeholder={t('stepUp.totpPlaceholder')}
                  required
                  autoComplete="one-time-code"
                />
              )}
              <Button type="submit" className="w-full" loading={loading === 'password'} disabled={loading !== null}>
                {t('stepUp.continue')}
              </Button>
            </form>
          )}

          <Dialog.Close asChild>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="mt-3 w-full border border-border hover:border-foreground/40"
            >
              {t('stepUp.cancel')}
            </Button>
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
