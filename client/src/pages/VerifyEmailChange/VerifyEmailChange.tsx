import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { verifyEmailChange, cancelEmailChange } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function VerifyEmailChange() {
  const { t } = useTranslation('auth');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await verifyEmailChange({ code });
      navigate('/settings');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('verifyEmailChange.verificationFailed'));
    }
    setLoading(false);
  };

  const handleCancel = async () => {
    await cancelEmailChange();
    navigate('/settings');
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">{t('verifyEmailChange.title')}</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input label={t('verifyEmailChange.verificationCodeLabel')} value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="off" />
          <Button type="submit" loading={loading}>{t('verifyEmailChange.verify')}</Button>
        </form>
        <div className="mt-4">
          <Button variant="ghost" size="sm" onClick={handleCancel}>{t('verifyEmailChange.cancel')}</Button>
        </div>
      </Card>
    </div>
  );
}
