import { useState, useEffect } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { register, getRegistrationInfo } from '@/api/auth';
import { getAuthInfo, type AuthInfo } from '@/api/passkeys';
import { useAuthStore } from '@/stores/authStore';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function Register() {
  const { t } = useTranslation('auth');
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [confirmTouched, setConfirmTouched] = useState(false);
  const [inviteCode, setInviteCode] = useState(searchParams.get('invite') || '');
  const [captcha, setCaptcha] = useState('');
  const [captchaSvg, setCaptchaSvg] = useState('');
  const [captchaQuestion, setCaptchaQuestion] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<'credentials' | 'captcha'>('credentials');
  const [requireInvite, setRequireInvite] = useState(false);
  const [registrationDisabled, setRegistrationDisabled] = useState(false);
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  // Instances with legal pages (ENABLE_LEGAL) require terms acceptance and a
  // separate explicit health-data consent (Art. 9(2)(a) GDPR) to register.
  const [legalEnabled, setLegalEnabled] = useState(false);
  const [legalAccepted, setLegalAccepted] = useState(false);
  const [healthConsent, setHealthConsent] = useState(false);
  const navigate = useNavigate();
  const { fetchUser } = useAuthStore();

  useEffect(() => {
    getRegistrationInfo().then((info) => {
      if (!info.registrationEnabled) setRegistrationDisabled(true);
      else if (info.inviteRequired) setRequireInvite(true);
      if (info.legalEnabled) setLegalEnabled(true);
    }).catch(() => {});
    getAuthInfo().then(setAuthInfo).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (step === 'credentials' && password !== confirmPassword) {
      setError(t('register.passwordsDoNotMatch'));
      return;
    }
    setLoading(true);
    try {
      const result = await register({
        step,
        email: step === 'credentials' ? email : undefined,
        password: step === 'credentials' ? password : undefined,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        captcha: step === 'captcha' ? captcha : undefined,
        invite_code: step === 'credentials' ? inviteCode : undefined,
        legal_accepted: step === 'credentials' && legalEnabled ? legalAccepted : undefined,
        health_consent: step === 'credentials' && legalEnabled ? healthConsent : undefined,
      });
      if (result.requireInviteCode) { setRequireInvite(true); setLoading(false); return; }
      if (result.requireCaptcha && result.captchaSvg) { setCaptchaSvg(result.captchaSvg); setCaptchaQuestion(result.captchaQuestion || ''); setStep('captcha'); setCaptcha(''); setLoading(false); return; }
      if (result.requireVerification) { navigate('/verify-email'); return; }
      if (result.ok) { await fetchUser(); navigate('/dashboard'); }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (typeof err.data.captchaSvg === 'string') setCaptchaSvg(err.data.captchaSvg);
        if (typeof err.data.captchaQuestion === 'string') setCaptchaQuestion(err.data.captchaQuestion);
        if (err.data.requireInviteCode) setRequireInvite(true);
      } else {
        setError(t('register.couldNotRegister'));
      }
      setLoading(false);
    }
  };

  if (registrationDisabled) {
    return (
      <div className="flex justify-center py-12">
        <Card className="w-full max-w-sm">
          <h2 className="mb-6 text-xl font-semibold">{t('register.title')}</h2>
          <Alert type="warning" message={t('register.registrationDisabled')} className="mb-4" />
          <div className="mt-6 text-sm">
            <Link to="/login">{t('register.alreadyHaveAccount')}</Link>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">{t('register.title')}</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}

        {step === 'credentials' && authInfo && authInfo.oidc && (
          <div className="flex flex-col gap-2 mb-2">
            <Button type="button" variant="outline" className="w-full"
              onClick={() => { window.location.href = '/auth/oidc/login'; }}>
              {authInfo.oidc.logo && (
                <img src={authInfo.oidc.logo} alt="" className="inline-block w-5 h-5 mr-2 align-middle"
                  onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} />
              )}
              {t('register.signUpWithProvider', { provider: authInfo.oidc.label })}
            </Button>
            <div className="relative my-2">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
              <div className="relative flex justify-center text-xs"><span className="bg-card px-2 text-muted-foreground">{t('register.or')}</span></div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {step === 'credentials' ? (
            <>
              <Input label={t('register.emailLabel')} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              <Input label={t('register.passwordLabel')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" minLength={10} placeholder={t('register.passwordPlaceholder')} />
              <Input
                label={t('register.confirmPasswordLabel')}
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                onBlur={() => setConfirmTouched(true)}
                error={confirmTouched && password !== confirmPassword ? t('register.passwordsDoNotMatch') : undefined}
                className={confirmTouched && password === confirmPassword ? 'border-green-500 focus-visible:ring-green-500' : undefined}
              />
              {requireInvite && (
                <Input label={t('register.inviteCodeLabel')} value={inviteCode} onChange={(e) => setInviteCode(e.target.value)} required placeholder={t('register.inviteCodePlaceholder')} />
              )}
              {legalEnabled && (
                <div className="flex flex-col gap-3 text-sm">
                  <label className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      checked={legalAccepted}
                      onChange={(e) => setLegalAccepted(e.target.checked)}
                      className="mt-1"
                      aria-label={t('register.consent.termsCheckboxAriaLabel')}
                    />
                    <span className="text-muted-foreground">
                      <Trans
                        i18nKey="register.consent.termsText"
                        ns="auth"
                        components={{
                          termsLink: <a href="/terms" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
                          privacyLink: <a href="/privacy" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
                        }}
                      />
                    </span>
                  </label>
                  <label className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      checked={healthConsent}
                      onChange={(e) => setHealthConsent(e.target.checked)}
                      className="mt-1"
                      aria-label={t('register.consent.healthCheckboxAriaLabel')}
                    />
                    <span className="text-muted-foreground">
                      {t('register.consent.healthText')}
                    </span>
                  </label>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="flex justify-center rounded-md bg-muted/50 p-2 invert [&_img]:max-w-full">
                <img src={`data:image/svg+xml;base64,${btoa(captchaSvg)}`} alt={t('register.captchaAltText')} />
              </div>
              {captchaQuestion && (
                <p className="text-sm text-muted-foreground">
                  {t('register.captchaFallbackQuestion', { question: captchaQuestion })}
                </p>
              )}
              <Input label={t('register.captchaLabel')} value={captcha} onChange={(e) => setCaptcha(e.target.value)} required autoComplete="off" />
            </div>
          )}
          <Button type="submit" loading={loading} disabled={step === 'credentials' && (!email || !password || !confirmPassword || password !== confirmPassword || (legalEnabled && (!legalAccepted || !healthConsent)))}>{step === 'credentials' ? t('register.continue') : t('register.submit')}</Button>
        </form>
        <div className="mt-6 text-sm">
          <Link to="/login">{t('register.alreadyHaveAccount')}</Link>
        </div>
      </Card>
    </div>
  );
}
