import { useState } from 'react';
import { useNavigate } from 'react-router';
import { api, ApiError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function DeleteAccount() {
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { user, clearUser } = useAuthStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api('/delete', {
        method: 'POST',
        body: JSON.stringify({ password, token: token || undefined }),
      });
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
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <Input label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            {user?.totpEnabled && (
              <Input label="2FA Code" value={token} onChange={(e) => setToken(e.target.value)} inputMode="numeric" />
            )}
            <Button type="submit" variant="destructive" loading={loading}>Delete My Account</Button>
          </form>
        )}
      </Card>
    </div>
  );
}
