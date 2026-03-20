import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { login, reset2fa } from '@/api/auth';
import { useAuthStore } from '@/stores/authStore';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [captcha, setCaptcha] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [requireToken, setRequireToken] = useState(false);
  const [canReset2fa, setCanReset2fa] = useState(false);
  const [captchaSvg, setCaptchaSvg] = useState('');
  const [resetMode, setResetMode] = useState<false | 'request' | 'verify'>(false);
  const [resetEmail, setResetEmail] = useState('');
  const [resetPassword, setResetPassword] = useState('');
  const [resetCode, setResetCode] = useState('');
  const navigate = useNavigate();
  const { fetchUser } = useAuthStore();

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
        if (err.data.requireCaptcha) setCaptcha('');
      } else { setError('Could not log in.'); }
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
      setError(err instanceof ApiError ? err.message : 'Could not send reset code.');
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
        setSuccess(result.message || '2FA has been disabled. You can now log in.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not verify code.');
    }
    setLoading(false);
  };

  if (resetMode === 'request') {
    return (
      <div className="flex justify-center py-12">
        <Card className="w-full max-w-sm">
          <h2 className="mb-2 text-xl font-semibold">Reset 2FA</h2>
          <p className="text-sm text-muted-foreground mb-4">Enter your credentials. We'll send a verification code to your email.</p>
          {error && <Alert type="error" message={error} className="mb-4" />}
          <form onSubmit={handleResetRequest} className="flex flex-col gap-4">
            <Input label="Email" type="email" value={resetEmail} onChange={(e) => setResetEmail(e.target.value)} required autoComplete="email" />
            <Input label="Password" type="password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} required autoComplete="current-password" />
            <Button type="submit" loading={loading}>Send Reset Code</Button>
          </form>
          <button type="button" onClick={() => { setResetMode(false); setError(''); }} className="mt-4 text-sm text-muted-foreground hover:text-primary transition-colors">
            Back to login
          </button>
        </Card>
      </div>
    );
  }

  if (resetMode === 'verify') {
    return (
      <div className="flex justify-center py-12">
        <Card className="w-full max-w-sm">
          <h2 className="mb-2 text-xl font-semibold">Reset 2FA</h2>
          <p className="text-sm text-muted-foreground mb-4">Enter the verification code sent to your email.</p>
          {error && <Alert type="error" message={error} className="mb-4" />}
          <form onSubmit={handleResetVerify} className="flex flex-col gap-4">
            <Input label="Verification Code" value={resetCode} onChange={(e) => setResetCode(e.target.value)} required inputMode="numeric" maxLength={6} placeholder="Enter 6-digit code" autoComplete="one-time-code" />
            <Button type="submit" loading={loading}>Verify & Disable 2FA</Button>
          </form>
          <button type="button" onClick={() => { setResetMode(false); setError(''); }} className="mt-4 text-sm text-muted-foreground hover:text-primary transition-colors">
            Back to login
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">Log In</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {!requireToken ? (
            <>
              <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              <Input label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
              {captchaSvg && (
                <div className="flex flex-col gap-2">
                  <div className="flex justify-center rounded-md bg-muted/50 p-2 invert [&_img]:max-w-full">
                    <img src={`data:image/svg+xml;base64,${btoa(captchaSvg)}`} alt="Captcha" />
                  </div>
                  <Input label="Captcha" value={captcha} onChange={(e) => setCaptcha(e.target.value)} required autoComplete="off" />
                </div>
              )}
            </>
          ) : (
            <>
              <Input label="2FA Code" type="text" value={token} onChange={(e) => setToken(e.target.value)} required autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" />
              <p className="text-xs text-muted-foreground">You can also enter a backup code.</p>
            </>
          )}
          <Button type="submit" loading={loading}>{requireToken ? 'Verify' : 'Log In'}</Button>
        </form>
        <div className="mt-6 flex justify-between text-sm">
          {requireToken && canReset2fa ? (
            <button type="button" onClick={() => { setResetMode('request'); setResetEmail(email); setResetPassword(password); setError(''); setSuccess(''); }} className="text-primary hover:underline">
              Lost your authenticator?
            </button>
          ) : (
            <Link to="/forgot-password">Forgot password?</Link>
          )}
          <Link to="/register">Create account</Link>
        </div>
      </Card>
    </div>
  );
}
