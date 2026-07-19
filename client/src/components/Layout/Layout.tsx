import { Suspense } from 'react';
import { Outlet, useLocation } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';
import Header from './Header';
import Footer from './Footer';
import Sidebar from './Sidebar';
import BottomNav from './BottomNav';

export default function Layout() {
  const user = useAuthStore((s) => s.user);
  const { pathname } = useLocation();
  // Admin tables need more width than the app column.
  const wide = pathname.startsWith('/admin');

  if (!user) {
    return (
      <div className="flex min-h-screen flex-col overflow-x-hidden">
        <Header />
        <main className="mx-auto w-full max-w-[1100px] flex-1 overflow-x-hidden px-4 pt-2 pb-8">
          <Suspense fallback={null}>
            <Outlet />
          </Suspense>
        </main>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen overflow-x-hidden">
      <Sidebar />
      <div className="flex min-h-screen flex-col lg:pl-[220px]">
        <main className={cn(
          'mx-auto w-full flex-1 overflow-x-hidden px-4 pt-3 pb-[calc(5.5rem+env(safe-area-inset-bottom))] lg:pb-8',
          wide ? 'max-w-[1000px]' : 'max-w-2xl',
        )}>
          <Suspense fallback={null}>
            <Outlet />
          </Suspense>
        </main>
        <div className="pb-[calc(4rem+env(safe-area-inset-bottom))] lg:pb-0">
          <Footer />
        </div>
      </div>
      <BottomNav />
    </div>
  );
}
