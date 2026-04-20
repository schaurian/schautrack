import { useState, useEffect } from 'react';
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
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [confirmTouched, setConfirmTouched] = useState(false);
  const [inviteCode, setInviteCode] = useState(searchParams.get('invite') || '');
  const [captcha, setCaptcha] = useState('');
  const [captchaSvg, setCaptchaSvg] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<'credentials' | 'captcha'>('credentials');
  const [requireInvite, setRequireInvite] = useState(false);
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const navigate = useNavigate();
  const { fetchUser } = useAuthStore();

  useEffect(() => {
    getRegistrationInfo().then((info) => {
      if (!info.registrationEnabled) setRequireInvite(true);
    }).catch(() => {});
    getAuthInfo().then(setAuthInfo).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (step === 'credentials' && password !== confirmPassword) {
      setError('Passwords do not match.');
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
      });
      if (result.requireInviteCode) { setRequireInvite(true); setLoading(false); return; }
      if (result.requireCaptcha && result.captchaSvg) { setCaptchaSvg(result.captchaSvg); setStep('captcha'); setCaptcha(''); setLoading(false); return; }
      if (result.requireVerification) { navigate('/verify-email'); return; }
      if (result.ok) { await fetchUser(); navigate('/dashboard'); }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (typeof err.data.captchaSvg === 'string') setCaptchaSvg(err.data.captchaSvg);
        if (err.data.requireInviteCode) setRequireInvite(true);
      } else {
        setError('Could not register.');
      }
      setLoading(false);
    }
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">Create Account</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}

        {step === 'credentials' && authInfo && authInfo.oidc && (
          <div className="flex flex-col gap-2 mb-2">
            <Button type="button" variant="outline" className="w-full"
              onClick={() => { window.location.href = '/auth/oidc/login'; }}>
              {authInfo.oidc.logo && (
                <img src={authInfo.oidc.logo} alt="" className="inline-block w-5 h-5 mr-2 align-middle"
                  onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} />
              )}
              Sign up with {authInfo.oidc.label}
            </Button>
            <div className="relative my-2">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
              <div className="relative flex justify-center text-xs"><span className="bg-card px-2 text-muted-foreground">or</span></div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {step === 'credentials' ? (
            <>
              <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              <Input label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" minLength={10} placeholder="Minimum 10 characters" />
              <Input
                label="Confirm Password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                onBlur={() => setConfirmTouched(true)}
                error={confirmTouched && password !== confirmPassword ? 'Passwords do not match.' : undefined}
                className={confirmTouched && password === confirmPassword ? 'border-green-500 focus-visible:ring-green-500' : undefined}
              />
              {requireInvite && (
                <Input label="Invite Code" value={inviteCode} onChange={(e) => setInviteCode(e.target.value)} required placeholder="Enter your invite code" />
              )}
            </>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="flex justify-center rounded-md bg-muted/50 p-2 invert [&_img]:max-w-full">
                <img src={`data:image/svg+xml;base64,${btoa(captchaSvg)}`} alt="Captcha" />
              </div>
              <Input label="Captcha" value={captcha} onChange={(e) => setCaptcha(e.target.value)} required autoComplete="off" />
            </div>
          )}
          <Button type="submit" loading={loading} disabled={step === 'credentials' && (!email || !password || !confirmPassword || password !== confirmPassword)}>{step === 'credentials' ? 'Continue' : 'Create Account'}</Button>
        </form>
        <div className="mt-6 text-sm">
          <Link to="/login">Already have an account?</Link>
        </div>
      </Card>
    </div>
  );
}
