import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { resetPassword } from '@/api/auth';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function ResetPassword() {
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
        setSuccess('Password updated. You can now log in.');
        setTimeout(() => navigate('/login'), 2000);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Reset failed.');
    }
    setLoading(false);
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">Reset Password</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        {success && <Alert type="success" message={success} className="mb-4" />}
        {!success && (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {!codeVerified ? (
              <Input label="Reset Code" value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="off" />
            ) : (
              <>
                <Input label="New Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={10} />
                <Input label="Confirm Password" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
              </>
            )}
            <Button type="submit" loading={loading}>{codeVerified ? 'Reset Password' : 'Verify Code'}</Button>
          </form>
        )}
        <div className="mt-6 text-sm">
          <Link to="/login">Back to login</Link>
        </div>
      </Card>
    </div>
  );
}
