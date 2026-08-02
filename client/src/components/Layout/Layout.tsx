import { Suspense } from 'react';
import { Outlet } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import Header from './Header';
import Footer from './Footer';
import Sidebar from './Sidebar';
import BottomNav from './BottomNav';

export default function Layout() {
  const user = useAuthStore((s) => s.user);

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
        {/* On mobile the tab-bar clearance lives on the footer wrapper below,
            so main only needs ordinary bottom padding — reserving it in both
            places is what left a canyon between the last card and the footer. */}
        <main className="mx-auto w-full max-w-4xl flex-1 overflow-x-hidden px-4 pt-3 pb-4 lg:pb-8">
          <Suspense fallback={null}>
            <Outlet />
          </Suspense>
        </main>
        <div className="pb-[calc(4rem+env(safe-area-inset-bottom))] opacity-60 lg:pb-0 lg:opacity-100">
          <Footer />
        </div>
      </div>
      <BottomNav />
    </div>
  );
}
