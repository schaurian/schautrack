import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { forgotPassword, getCaptcha } from '@/api/auth';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [captcha, setCaptcha] = useState('');
  const [captchaSvg, setCaptchaSvg] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    getCaptcha().then((data) => setCaptchaSvg(data.svg)).catch(() => setError('Failed to load captcha'));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await forgotPassword({ email, captcha });
      navigate('/reset-password');
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (err.data.captchaSvg) setCaptchaSvg(err.data.captchaSvg as string);
      } else {
        setError('Request failed.');
      }
      setCaptcha('');
      setLoading(false);
    }
  };

  return (
    <div className="flex justify-center py-12">
      <Card className="w-full max-w-sm">
        <h2 className="mb-6 text-xl font-semibold">Forgot Password</h2>
        {error && <Alert type="error" message={error} className="mb-4" />}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          {captchaSvg && (
            <div className="flex flex-col gap-2">
              <div className="flex justify-center rounded-md bg-muted/50 p-2 invert [&_img]:max-w-full">
                <img src={`data:image/svg+xml;base64,${btoa(captchaSvg)}`} alt="Captcha" />
              </div>
              <Input label="Captcha" value={captcha} onChange={(e) => setCaptcha(e.target.value)} required autoComplete="off" />
            </div>
          )}
          <Button type="submit" loading={loading}>Send Reset Code</Button>
        </form>
      </Card>
    </div>
  );
}
