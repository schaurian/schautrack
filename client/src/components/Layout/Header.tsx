import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { useAuthStore } from '@/stores/authStore';

// Guest-only top bar. The authenticated shell (Sidebar + BottomNav in Layout)
// replaced the old in-header navigation.
export default function Header() {
  const { t } = useTranslation('common');
  const user = useAuthStore((s) => s.user);

  return (
    <header className="relative z-50">
      <div className="mx-auto flex max-w-[1100px] items-center justify-between px-4 py-3">
        <Link to={user ? '/dashboard' : '/'} className="flex items-center gap-2 text-foreground no-underline">
          <div className="size-12 rounded-[10px] bg-card border border-border shadow-[0_10px_30px_rgba(0,0,0,0.35)] overflow-hidden grid place-items-center shrink-0">
            <img src="/logo-128.webp" alt="" width={48} height={48} decoding="async" className="w-full h-full object-cover block" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[18px] font-bold tracking-tight">{t('app.name')}</span>
            <span className="text-[13px] text-muted-foreground">{t('header.tagline')}</span>
          </div>
        </Link>

        {!user && (
          <nav className="flex items-center gap-1">
            <Link to="/login"
              className="rounded-md px-3 py-2 text-base text-foreground transition-colors hover:bg-surface-hover hover:text-foreground">
              {t('nav.login')}
            </Link>
            <Link to="/register"
              className="rounded-md px-3 py-2 text-base text-foreground transition-colors hover:bg-surface-hover hover:text-foreground">
              {t('nav.register')}
            </Link>
          </nav>
        )}
      </div>
    </header>
  );
}
