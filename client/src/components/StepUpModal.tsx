import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { startAuthentication } from '@simplewebauthn/browser';
import { useStepUpStore } from '@/stores/stepUpStore';
import { useAuthStore } from '@/stores/authStore';
import { stepUpPasswordTOTP, stepUpPasskeyBegin, stepUpPasskeyFinish } from '@/api/stepup';
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
  const pending = useStepUpStore((s) => s.pending);
  const clear = useStepUpStore((s) => s.clear);
  const userEmail = useAuthStore((s) => s.user?.email);

  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState<'password' | 'passkey' | null>(null);

  // Reset form when the modal opens for a new request.
  useEffect(() => {
    if (pending) {
      setPassword('');
      setToken('');
      setError('');
      setLoading(null);
    }
  }, [pending]);

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
      setError(err instanceof ApiError ? err.message : 'Step-up failed');
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
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : 'Passkey step-up failed');
      setLoading(null);
    }
  };

  const hasPassword = pending?.methods.includes('password') ?? false;
  const hasPasskey = pending?.methods.includes('passkey') ?? false;
  const noMethods = !!pending && !hasPassword && !hasPasskey;

  return (
    <Dialog.Root open={!!pending} onOpenChange={(open) => { if (!open) cancel(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-card p-6 text-card-foreground shadow-lg focus:outline-none"
        >
          <Dialog.Title className="text-base font-semibold mb-1">Confirm it's you</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-4">
            This change requires fresh authentication.
          </Dialog.Description>

          {error && <Alert type="error" message={error} className="mb-4" />}

          {noMethods && (
            <Alert
              type="error"
              message="No re-authentication method available. Log out and back in to make this change, or set a password / add a passkey first."
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
              Use passkey
            </Button>
          )}

          {hasPassword && hasPasskey && (
            <div className="relative my-3">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
              <div className="relative flex justify-center text-xs">
                <span className="bg-card px-2 text-muted-foreground">or</span>
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
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                autoFocus
              />
              {pending?.totpRequired && (
                <Input
                  label="2FA Code"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  inputMode="numeric"
                  maxLength={8}
                  placeholder="6-digit code or backup code"
                  required
                  autoComplete="one-time-code"
                />
              )}
              <Button type="submit" className="w-full" loading={loading === 'password'} disabled={loading !== null}>
                Continue
              </Button>
            </form>
          )}

          <Dialog.Close asChild>
            <button
              type="button"
              className="mt-4 w-full text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Cancel
            </button>
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
