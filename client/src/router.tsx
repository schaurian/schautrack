import { lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import Layout from '@/components/Layout/Layout';
import Landing from '@/pages/Landing/Landing';
import Login from '@/pages/Login/Login';
import Register from '@/pages/Register/Register';
import ForgotPassword from '@/pages/ForgotPassword/ForgotPassword';
import ResetPassword from '@/pages/ResetPassword/ResetPassword';
import VerifyEmail from '@/pages/VerifyEmail/VerifyEmail';

// The authenticated and legal pages are code-split into their own chunks so
// the initial (unauthenticated) load no longer ships the entire app.
const Dashboard = lazy(() => import('@/pages/Dashboard/Dashboard'));
const Plan = lazy(() => import('@/pages/Plan/Plan'));
const Settings = lazy(() => import('@/pages/Settings/Settings'));
const Admin = lazy(() => import('@/pages/Admin/Admin'));
const Privacy = lazy(() => import('@/pages/Legal/Privacy'));
const Terms = lazy(() => import('@/pages/Legal/Terms'));
const Imprint = lazy(() => import('@/pages/Legal/Imprint'));
const DeleteAccount = lazy(() => import('@/pages/Delete/DeleteAccount'));
const VerifyEmailChange = lazy(() => import('@/pages/VerifyEmailChange/VerifyEmailChange'));

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
        <Route path="/plan" element={<ProtectedRoute><Plan /></ProtectedRoute>} />
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
