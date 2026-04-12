import { useState } from 'react';
import { savePassword } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  totpEnabled: boolean;
}

export default function PasswordSettings({ totpEnabled }: Props) {
  const [current, setCurrent] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [totp, setTotp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      await savePassword({ current_password: current, new_password: newPw, confirm_password: confirm, totp_code: totp || undefined });
      setSuccess('Password updated.');
      setCurrent(''); setNewPw(''); setConfirm(''); setTotp('');
      addToast('success', 'Password updated');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed.');
    }
    setLoading(false);
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Change Password</h3>
      {error && <Alert type="error" message={error} />}
      {success && <Alert type="success" message={success} />}
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <Input label="Current Password" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        <Input label="New Password" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} required minLength={10} />
        <Input label="Confirm Password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        {totpEnabled && <Input label="2FA Code" value={totp} onChange={(e) => setTotp(e.target.value)} inputMode="numeric" />}
        <div className="border-t border-border pt-3 mt-1">
          <Button type="submit" className="w-full" loading={loading}>Update Password</Button>
        </div>
      </form>
    </Card>
  );
}
