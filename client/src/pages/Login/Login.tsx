import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { login, reset2fa } from '@/api/auth';
import { getAuthInfo, passkeyLoginBegin, passkeyLoginFinish, type AuthInfo } from '@/api/passkeys';
import { useAuthStore } from '@/stores/authStore';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { startAuthentication } from '@simplewebauthn/browser';

export default function Login() {
  const { t } = useTranslation('auth');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [captcha, setCaptcha] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [requireToken, setRequireToken] = useState(false);
  const [canReset2fa, setCanReset2fa] = useState(false);
  const [captchaSvg, setCaptchaSvg] = useState('');
  const [captchaQuestion, setCaptchaQuestion] = useState('');
  const [resetMode, setResetMode] = useState<false | 'request' | 'verify'>(false);
  const [resetEmail, setResetEmail] = useState('');
  const [resetPassword, setResetPassword] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { fetchUser } = useAuthStore();

  useEffect(() => {
    getAuthInfo().then(setAuthInfo).catch(() => {});
  }, []);

  // Surface OIDC redirect failures (?error=...). Strip the param after
  // reading so a refresh doesn't show the same error again.
  useEffect(() => {
    const code = searchParams.get('error');
    if (!code) return;
    const msg = t('oidc.login.' + code, { defaultValue: t('oidc.login.generic') });
    setError(msg);
    const next = new URLSearchParams(searchParams);
    next.delete('error');
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const handlePasskeyLogin = async () => {
    setPasskeyLoading(true);
    setError('');
    try {
      const options = await passkeyLoginBegin();
      const credential = await startAuthentication({ optionsJSON: options as any });
      await passkeyLoginFinish(credential as any);
      await fetchUser();
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : t('login.passkeyLoginFailed'));
    }
    setPasskeyLoading(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const result = await login({
        email, password,
        token: requireToken ? token : undefined,
        captcha: captchaSvg ? captcha : undefined,
      });
      if (result.requireToken) {
        setRequireToken(true);
        if (result.canReset2fa) setCanReset2fa(true);
        setLoading(false);
        return;
      }
      if (result.requireVerification) { navigate('/verify-email'); return; }
      if (result.ok) { await fetchUser(); navigate('/dashboard'); }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (typeof err.data.captchaSvg === 'string') setCaptchaSvg(err.data.captchaSvg);
        if (typeof err.data.captchaQuestion === 'string') setCaptchaQuestion(err.data.captchaQuestion);
        if (err.data.requireCaptcha) setCaptcha('');
      } else { setError(t('login.couldNotLogIn')); }
      setLoading(false);
    }
  };

  const handleResetRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await reset2fa({ step: 'request', email: resetEmail, password: resetPassword });
      if (result.ok) {
        setResetMode('verify');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('login.couldNotSendResetCode'));
    }
    setLoading(false);
  };

  const handleResetVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await reset2fa({ step: 'verify', code: resetCode });
      if (result.ok) {
        setResetMode(false);
        setRequireToken(false);
        setCanReset2fa(false);
        setToken('');
        setSuccess(result.message || t('login.twoFaRemovedSuccess'));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('login.couldNotVerifyCode'));
    }
    setLoading(false);
  };

  if (resetMode === 'request') {
    return (
      <div className="flex justify-center py-12">
        <Card className="w-full max-w-sm rounded-2xl border border-border bg-card/60 p-6 first:pt-6 last:border">
          <h2 className="mb-2 text-xl font-semibold">{t('login.reset2faTitle')}</h2>
          <p className="text-sm text-muted-foreground mb-4">{t('login.reset2faRequestDescription')}</p>
          {error && <Alert type="error" message={error} className="mb-4" />}
          <form onSubmit={handleResetRequest} className="flex flex-col gap-4">
            <Input label={t('login.emailLabel')} type="email" value={resetEmail} onChange={(e) => setResetEmail(e.target.value)} required autoComplete="email" />
            <Input label={t('login.passwordLabel')} type="password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} required autoComplete="current-password" />
            <Button type="submit" loading={loading}>{t('login.sendResetCode')}</Button>
          </form>
          <button type="button" onClick={() => { setResetMode(false); setError(''); }} className="mt-4 text-sm text-muted-foreground hover:text-primary transition-colors">
            {t('login.backToLogin')}
          </button>
        </Card>
      </div>
    );
  }

  if (resetMode === 'verify') {
    return (
      <div className="flex justify-center py-12">
        <Card className="w-full max-w-sm rounded-2xl border border-border bg-card/60 p-6 first:pt-6 last:border">
          <h2 className="mb-2 text-xl font-semibold">{t('login.reset2faTitle')}</h2>
          <p className="text-sm text-muted-foreground mb-4">{t('login.reset2faVerifyDescription')}</p>
          {error && <Alert type="error" message={error} className="mb-4" />}
          <form onSubmit={handleResetVerify} className="flex flex-col gap-4">
            <Input label={t('login.verificationCodeLabel')} value={resetCode} onChange={(e) => setResetCode(e.target.value)} required inputMode="numeric" maxLength={6} placeholder={t('login.verificationCodePlaceholder')} autoComplete="one-time-code" />
            <Button type="submit" loading={loading}>{t('login.verifyAndRemove2fa')}</Button>
          </form>
          <button type="button" onClick={() => { setResetMode(false); setError(''); }} className="mt-4 text-sm text-muted-foreground hover:text-primary transition-colors">
            {t('login.backToLogin')}
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm rounded-2xl border border-border bg-card/60 p-6 first:pt-6 last:border">
        <h2 className="mb-6 text-xl font-semibold">{t('login.title')}</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}

        {!requireToken && !resetMode && authInfo && (authInfo.passkeysEnabled || authInfo.oidc) && (
          <div className="flex flex-col gap-2 mb-2">
            {authInfo.passkeysEnabled && (
              <Button type="button" variant="outline" className="w-full" loading={passkeyLoading} onClick={handlePasskeyLogin}>
                {t('login.signInWithPasskey')}
              </Button>
            )}
            {authInfo.oidc && (
              <Button type="button" variant="outline" className="w-full"
                onClick={() => { window.location.href = '/auth/oidc/login'; }}>
                {authInfo.oidc.logo && (
                  <img src={authInfo.oidc.logo} alt="" className="inline-block w-5 h-5 mr-2 align-middle"
                    onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} />
                )}
                {t('login.signInWithProvider', { provider: authInfo.oidc.label })}
              </Button>
            )}
            <div className="relative my-2">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
              <div className="relative flex justify-center text-xs"><span className="bg-card px-2 text-muted-foreground">{t('login.or')}</span></div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {!requireToken ? (
            <>
              <Input label={t('login.emailLabel')} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              <Input label={t('login.passwordLabel')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
              {captchaSvg && (
                <div className="flex flex-col gap-2">
                  <div className="flex justify-center rounded-md bg-muted/50 p-2 invert [&_img]:max-w-full">
                    <img src={`data:image/svg+xml;base64,${btoa(captchaSvg)}`} alt={t('login.captchaAltText')} />
                  </div>
                  {captchaQuestion && (
                    <p className="text-sm text-muted-foreground">
                      {t('login.captchaFallbackQuestion', { question: captchaQuestion })}
                    </p>
                  )}
                  <Input label={t('login.captchaLabel')} value={captcha} onChange={(e) => setCaptcha(e.target.value)} required autoComplete="off" />
                </div>
              )}
            </>
          ) : (
            <>
              <Input label={t('login.twoFactorCodeLabel')} type="text" value={token} onChange={(e) => setToken(e.target.value)} required autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" />
              <p className="text-xs text-muted-foreground">{t('login.backupCodeHint')}</p>
            </>
          )}
          <Button type="submit" loading={loading}>{requireToken ? t('login.verify') : t('login.submit')}</Button>
        </form>
        <div className="mt-6 flex flex-col gap-2 text-sm">
          <div className="flex justify-between">
            {!requireToken && <Link to="/forgot-password">{t('login.forgotPassword')}</Link>}
            {requireToken && canReset2fa && (
              <button type="button" onClick={() => { setResetMode('request'); setResetEmail(email); setResetPassword(password); setError(''); setSuccess(''); }} className="text-primary hover:underline">
                {t('login.lostAuthenticator')}
              </button>
            )}
            {requireToken && !canReset2fa && (
              <span className="text-muted-foreground/50 cursor-default" title={t('login.lostAuthenticatorTitle')}>
                {t('login.lostAuthenticator')}
              </span>
            )}
            <Link to="/register">{t('login.createAccount')}</Link>
          </div>
        </div>
      </Card>
    </div>
  );
}
