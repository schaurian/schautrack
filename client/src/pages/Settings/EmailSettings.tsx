import { useState } from 'react';
import { useNavigate } from 'react-router';
import { requestEmailChange } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface Props {
  currentEmail: string;
  totpEnabled: boolean;
}

export default function EmailSettings({ currentEmail, totpEnabled }: Props) {
  const navigate = useNavigate();
  const [newEmail, setNewEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await requestEmailChange({
        new_email: newEmail,
        password,
        totp_code: totp || undefined,
      });
      if (res.ok) {
        navigate('/settings/email/verify');
      } else {
        setError(res.error || 'Failed to request email change.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to request email change.');
    }
    setLoading(false);
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Change Email</h3>
      <p className="text-muted-foreground text-xs mb-3">
        Current: {currentEmail}
      </p>
      {error && <Alert type="error" message={error} />}
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <Input
          label="New Email"
          type="email"
          value={newEmail}
          onChange={(e) => setNewEmail(e.target.value)}
          required
        />
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {totpEnabled && (
          <Input
            label="2FA Code"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            inputMode="numeric"
            maxLength={6}
          />
        )}
        <div className="border-t border-border pt-3 mt-1">
          <Button type="submit" className="w-full" loading={loading}>Send Verification Code</Button>
        </div>
      </form>
    </Card>
  );
}
