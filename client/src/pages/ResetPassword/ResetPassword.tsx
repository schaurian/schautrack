import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { resetPassword } from '@/api/auth';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function ResetPassword() {
  const { t } = useTranslation('auth');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [codeVerified, setCodeVerified] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (!codeVerified) {
        const result = await resetPassword({ code });
        if (result.codeVerified) {
          setCodeVerified(true);
        }
      } else {
        await resetPassword({ password, confirm_password: confirmPassword });
        setSuccess(t('resetPassword.passwordUpdatedSuccess'));
        setTimeout(() => navigate('/login'), 2000);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('resetPassword.resetFailed'));
    }
    setLoading(false);
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">{t('resetPassword.title')}</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}
        {!success && (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {!codeVerified ? (
              <Input label={t('resetPassword.resetCodeLabel')} value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" />
            ) : (
              <>
                <Input label={t('resetPassword.newPasswordLabel')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={10} autoComplete="new-password" />
                <Input label={t('resetPassword.confirmPasswordLabel')} type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required autoComplete="new-password" />
              </>
            )}
            <Button type="submit" loading={loading}>{codeVerified ? t('resetPassword.submitReset') : t('resetPassword.verifyCode')}</Button>
          </form>
        )}
        <div className="mt-6 text-sm">
          <Link to="/login">{t('resetPassword.backToLogin')}</Link>
        </div>
      </Card>
    </div>
  );
}
