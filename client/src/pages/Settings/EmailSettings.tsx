import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { requestEmailChange } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface Props {
  currentEmail: string;
}

export default function EmailSettings({ currentEmail }: Props) {
  const { t } = useTranslation('settings');
  const navigate = useNavigate();
  const [newEmail, setNewEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await requestEmailChange({ new_email: newEmail });
      if (res.ok) {
        navigate('/settings/email/verify');
      } else {
        setError(res.error || t('email.requestFailed'));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('email.requestFailed'));
    }
    setLoading(false);
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">{t('email.heading')}</h3>
      <p className="text-muted-foreground text-xs mb-3">
        {t('email.current', { email: currentEmail })}
      </p>
      {error && <Alert type="error" message={error} />}
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <Input
          label={t('email.newEmailLabel')}
          type="email"
          value={newEmail}
          onChange={(e) => setNewEmail(e.target.value)}
          required
        />
        <div className="border-t border-border pt-3 mt-1">
          <Button type="submit" className="w-full" loading={loading}>{t('email.submit')}</Button>
        </div>
      </form>
    </Card>
  );
}
