import { useState } from 'react';
import { savePassword } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { useToastStore } from '@/stores/toastStore';

export default function PasswordSettings() {
  const [newPw, setNewPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    // Validate locally before triggering step-up — no point making the user
    // re-authenticate just to find out the new passwords don't match.
    if (newPw !== confirm) {
      setError('New passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      await savePassword({ new_password: newPw, confirm_password: confirm });
      setSuccess('Password updated.');
      setNewPw('');
      setConfirm('');
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
        {/*
          autoComplete="new-password" tells password managers these aren't
          login fields — without the hint they may try to autofill a stored
          credential (especially when the step-up modal opens on top of this
          form, with its own current-password field).
        */}
        <Input label="New Password" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} required minLength={10} autoComplete="new-password" />
        <Input label="Confirm Password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
        <div className="border-t border-border pt-3 mt-1">
          <Button type="submit" className="w-full" loading={loading}>Update Password</Button>
        </div>
      </form>
    </Card>
  );
}
