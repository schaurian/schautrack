import { useState } from 'react';
import { useNavigate } from 'react-router';
import { verifyEmailChange, cancelEmailChange } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function VerifyEmailChange() {
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
      setError(err instanceof ApiError ? err.message : 'Verification failed.');
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
        <h2 className="mb-6 text-xl font-semibold">Verify New Email</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input label="Verification Code" value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="off" />
          <Button type="submit" loading={loading}>Verify</Button>
        </form>
        <div className="mt-4">
          <Button variant="ghost" size="sm" onClick={handleCancel}>Cancel</Button>
        </div>
      </Card>
    </div>
  );
}
