import { useState } from 'react';
import { useNavigate } from 'react-router';
import { api, ApiError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function DeleteAccount() {
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { clearUser } = useAuthStore();

  const handleDelete = async () => {
    setError('');
    setLoading(true);
    try {
      await api('/delete', { method: 'POST' });
      setSuccess('Account deleted. Redirecting...');
      clearUser();
      setTimeout(() => navigate('/'), 2000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not delete account.');
    }
    setLoading(false);
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-2 text-xl font-semibold text-destructive">Delete Account</h2>
        <p className="mb-6 text-sm text-muted-foreground">
          This will permanently delete your account and all data. This cannot be undone.
        </p>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}
        {!success && (
          <div className="flex flex-col gap-4">
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={confirm}
                onChange={(e) => setConfirm(e.target.checked)}
                className="mt-1"
              />
              <span>I understand this is permanent and irreversible.</span>
            </label>
            <Button
              type="button"
              variant="destructive"
              loading={loading}
              disabled={!confirm}
              onClick={handleDelete}
            >
              Delete My Account
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}
