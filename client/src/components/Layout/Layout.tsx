import { Outlet } from 'react-router';
import Header from './Header';
import Footer from './Footer';

export default function Layout() {
  return (
    <div className="flex min-h-screen flex-col overflow-x-hidden">
      <Header />
      <main className="mx-auto w-full max-w-[1100px] flex-1 px-4 pt-2 pb-8 overflow-x-hidden">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
