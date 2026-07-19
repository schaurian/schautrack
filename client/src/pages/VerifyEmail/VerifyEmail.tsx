import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { verifyEmail, resendVerification } from '@/api/auth';
import { useAuthStore } from '@/stores/authStore';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function VerifyEmail() {
  const { t } = useTranslation('auth');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const navigate = useNavigate();
  const { fetchUser } = useAuthStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await verifyEmail({ code });
      if (result.ok) {
        await fetchUser();
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('verifyEmail.verificationFailed'));
    }
    setLoading(false);
  };

  const handleResend = async () => {
    setError('');
    setResending(true);
    try {
      const result = await resendVerification({});
      if (result.ok) setSuccess(t('verifyEmail.newCodeSent'));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('verifyEmail.couldNotResend'));
    }
    setResending(false);
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm rounded-2xl border border-border bg-card/60 p-6 first:pt-6 last:border">
        <h2 className="mb-6 text-xl font-semibold">{t('verifyEmail.title')}</h2>
        <p className="mb-6 text-sm text-muted-foreground">
          {t('verifyEmail.description')}
        </p>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input label={t('verifyEmail.verificationCodeLabel')} value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="off" />
          <Button type="submit" loading={loading}>{t('verifyEmail.verify')}</Button>
        </form>
        <div className="mt-4">
          <Button variant="ghost" size="sm" onClick={handleResend} loading={resending}>{t('verifyEmail.resendCode')}</Button>
        </div>
      </Card>
    </div>
  );
}
