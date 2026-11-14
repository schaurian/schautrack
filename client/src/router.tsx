import { Routes, Route, Navigate } from 'react-router';
import { lazyRoute } from '@/lib/lazyRoute';
import { useAuthStore } from '@/stores/authStore';
import Layout from '@/components/Layout/Layout';
import Landing from '@/pages/Landing/Landing';
import Login from '@/pages/Login/Login';

// The authenticated and legal pages are code-split into their own chunks so
// the initial (unauthenticated) load no longer ships the entire app. Landing
// and Login stay in the startup bundle: they are the signed-out cold-start
// pages, and an eager page renders in the same frame the session check lands.
// The other signed-out pages are split; a returning user (and every Android
// cold start, which opens /dashboard) never renders them.
const Register = lazyRoute(() => import('@/pages/Register/Register'));
const ForgotPassword = lazyRoute(() => import('@/pages/ForgotPassword/ForgotPassword'));
const ResetPassword = lazyRoute(() => import('@/pages/ResetPassword/ResetPassword'));
const VerifyEmail = lazyRoute(() => import('@/pages/VerifyEmail/VerifyEmail'));
const Dashboard = lazyRoute(() => import('@/pages/Dashboard/Dashboard'));
const Plan = lazyRoute(() => import('@/pages/Plan/Plan'));
const Settings = lazyRoute(() => import('@/pages/Settings/Settings'));
const Account = lazyRoute(() => import('@/pages/Account/Account'));
const Admin = lazyRoute(() => import('@/pages/Admin/Admin'));
const Privacy = lazyRoute(() => import('@/pages/Legal/Privacy'));
const Terms = lazyRoute(() => import('@/pages/Legal/Terms'));
const Imprint = lazyRoute(() => import('@/pages/Legal/Imprint'));
const DeleteAccount = lazyRoute(() => import('@/pages/Delete/DeleteAccount'));
const VerifyEmailChange = lazyRoute(() => import('@/pages/VerifyEmailChange/VerifyEmailChange'));

type Preload = () => Promise<unknown>;

// What a cold start to each path renders, signed out and signed in. A guest
// page redirects a signed-in user to /dashboard; a protected one sends a
// signed-out visitor to /login, which is eager and needs nothing.
const COLD_START: Record<string, { signedOut: Preload | null; signedIn: Preload | null }> = {
  '/': { signedOut: null, signedIn: Dashboard.preload },
  '/login': { signedOut: null, signedIn: Dashboard.preload },
  '/register': { signedOut: Register.preload, signedIn: Dashboard.preload },
  '/forgot-password': { signedOut: ForgotPassword.preload, signedIn: Dashboard.preload },
  '/reset-password': { signedOut: ResetPassword.preload, signedIn: Dashboard.preload },
  '/verify-email': { signedOut: VerifyEmail.preload, signedIn: VerifyEmail.preload },
  '/dashboard': { signedOut: null, signedIn: Dashboard.preload },
  '/plan': { signedOut: null, signedIn: Plan.preload },
  '/settings': { signedOut: null, signedIn: Settings.preload },
  '/account': { signedOut: null, signedIn: Account.preload },
};

/**
 * Start fetching the chunk for the page a cold start will render, before
 * /api/me answers.
 *
 * A lazy route is only requested once the router renders it, and the router
 * renders only after the session check — so a cold start to /dashboard paid
 * for the entry bundle, then /api/me, then the Dashboard chunk, one after the
 * other. Fetching the chunk at boot overlaps it with the other two, and a
 * chunk that has arrived by the first render renders without suspending (see
 * lazyRoute). `signedIn` is a hint (lib/sessionHint) — the session cookie is
 * HttpOnly — so a wrong guess costs one unused chunk, never a wrong page.
 */
export function preloadRouteChunk(pathname: string, signedIn: boolean) {
  const target = COLD_START[pathname.replace(/\/+$/, '') || '/'];
  const preload = target && (signedIn ? target.signedIn : target.signedOut);
  if (preload) void preload();
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
