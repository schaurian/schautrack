import { Routes, Route, Navigate } from 'react-router';
import { lazyRoute } from '@/lib/lazyRoute';
import { useAuthStore } from '@/stores/authStore';
import Layout from '@/components/Layout/Layout';

// The authenticated and legal pages are code-split into their own chunks so
// the initial (unauthenticated) load no longer ships the entire app.
// The signed-out pages are split too: a returning user (and every Android cold
// start, which opens /dashboard) never renders them. preloadRouteChunk below
// fetches the one being opened at boot, so a direct visit to /login does not
// wait for it.
const loadLanding = () => import('@/pages/Landing/Landing');
const loadLogin = () => import('@/pages/Login/Login');
const loadRegister = () => import('@/pages/Register/Register');
const loadForgotPassword = () => import('@/pages/ForgotPassword/ForgotPassword');
const loadResetPassword = () => import('@/pages/ResetPassword/ResetPassword');
const loadVerifyEmail = () => import('@/pages/VerifyEmail/VerifyEmail');
const Landing = lazyRoute(loadLanding);
const Login = lazyRoute(loadLogin);
const Register = lazyRoute(loadRegister);
const ForgotPassword = lazyRoute(loadForgotPassword);
const ResetPassword = lazyRoute(loadResetPassword);
const VerifyEmail = lazyRoute(loadVerifyEmail);
const loadDashboard = () => import('@/pages/Dashboard/Dashboard');
const loadPlan = () => import('@/pages/Plan/Plan');
const loadSettings = () => import('@/pages/Settings/Settings');
const loadAccount = () => import('@/pages/Account/Account');
const Dashboard = lazyRoute(loadDashboard);
const Plan = lazyRoute(loadPlan);
const Settings = lazyRoute(loadSettings);
const Account = lazyRoute(loadAccount);
const Admin = lazyRoute(() => import('@/pages/Admin/Admin'));
const Privacy = lazyRoute(() => import('@/pages/Legal/Privacy'));
const Terms = lazyRoute(() => import('@/pages/Legal/Terms'));
const Imprint = lazyRoute(() => import('@/pages/Legal/Imprint'));
const DeleteAccount = lazyRoute(() => import('@/pages/Delete/DeleteAccount'));
const VerifyEmailChange = lazyRoute(() => import('@/pages/VerifyEmailChange/VerifyEmailChange'));

// Pages a cold start lands on. The Android app opens /dashboard.
const PRELOADABLE: Record<string, () => Promise<unknown>> = {
  '/': loadLanding,
  '/login': loadLogin,
  '/register': loadRegister,
  '/forgot-password': loadForgotPassword,
  '/reset-password': loadResetPassword,
  '/verify-email': loadVerifyEmail,
  '/dashboard': loadDashboard,
  '/plan': loadPlan,
  '/settings': loadSettings,
  '/account': loadAccount,
};

/**
 * Start fetching the chunk for the page being opened, before /api/me answers.
 *
 * A lazy route is only requested once the router renders it, and the router
 * renders only after the session check — so a cold start to /dashboard paid
 * for the entry bundle, then /api/me, then the Dashboard chunk, one after the
 * other. Fetching the chunk at boot overlaps it with the other two. The module
 * map dedupes the import, so the lazy() that renders it later reuses this
 * request. A failure is ignored here; the route's own import reports it.
 */
export function preloadRouteChunk(pathname: string) {
  const load = PRELOADABLE[pathname.replace(/\/+$/, '') || '/'];
  if (load) load().catch(() => {});
}

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
        <Route path="/account" element={<ProtectedRoute><Account /></ProtectedRoute>} />
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
