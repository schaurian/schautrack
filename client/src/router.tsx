import { Routes, Route, Navigate } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import Layout from '@/components/Layout/Layout';
import Landing from '@/pages/Landing/Landing';
import Login from '@/pages/Login/Login';
import Register from '@/pages/Register/Register';
import ForgotPassword from '@/pages/ForgotPassword/ForgotPassword';
import ResetPassword from '@/pages/ResetPassword/ResetPassword';
import VerifyEmail from '@/pages/VerifyEmail/VerifyEmail';
import Dashboard from '@/pages/Dashboard/Dashboard';
import Settings from '@/pages/Settings/Settings';
import Admin from '@/pages/Admin/Admin';
import Privacy from '@/pages/Legal/Privacy';
import Terms from '@/pages/Legal/Terms';
import Imprint from '@/pages/Legal/Imprint';
import DeleteAccount from '@/pages/Delete/DeleteAccount';
import VerifyEmailChange from '@/pages/VerifyEmailChange/VerifyEmailChange';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuthStore();
  if (isLoading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function GuestRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuthStore();
  if (isLoading) return null;
  if (user) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

export default function AppRouter() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<GuestRoute><Landing /></GuestRoute>} />
        <Route path="/login" element={<GuestRoute><Login /></GuestRoute>} />
        <Route path="/register" element={<GuestRoute><Register /></GuestRoute>} />
        <Route path="/forgot-password" element={<GuestRoute><ForgotPassword /></GuestRoute>} />
        <Route path="/reset-password" element={<GuestRoute><ResetPassword /></GuestRoute>} />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
        <Route path="/delete" element={<ProtectedRoute><DeleteAccount /></ProtectedRoute>} />
        <Route path="/settings/email/verify" element={<ProtectedRoute><VerifyEmailChange /></ProtectedRoute>} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms" element={<Terms />} />
        <Route path="/imprint" element={<Imprint />} />
      </Route>
    </Routes>
  );
}
