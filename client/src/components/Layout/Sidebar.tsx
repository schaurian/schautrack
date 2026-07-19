import { useTranslation } from 'react-i18next';
import { Link, NavLink } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { useLogout } from '@/hooks/useLogout';
import { cn } from '@/lib/utils';

export default function Sidebar() {
  const { t } = useTranslation('common');
  const { user, isAdmin, pendingLinkRequests } = useAuthStore();
  const doLogout = useLogout();

  const navItem = ({ isActive }: { isActive: boolean }) => cn(
    'relative rounded-[10px] px-3 py-2 text-[15px] no-underline transition-colors',
    isActive ? 'bg-primary/12 font-semibold text-primary' : 'text-foreground hover:bg-surface-hover',
  );

  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-[220px] flex-col border-r border-divider bg-[#0a1120]/60 p-4 lg:flex">
      <Link to="/dashboard" className="mb-6 flex items-center gap-2.5 text-foreground no-underline">
        <div className="grid size-10 shrink-0 place-items-center overflow-hidden rounded-[10px] border border-border bg-card">
          <img src="/logo-128.webp" alt="" width={40} height={40} decoding="async" className="block h-full w-full object-cover" />
        </div>
        <div className="flex flex-col leading-none">
          <span className="font-display text-[16px] font-bold tracking-tight">{t('app.name')}</span>
          <span className="text-[12px] text-muted-foreground">{t('header.tagline')}</span>
        </div>
      </Link>

      <nav className="flex flex-col gap-1">
        <NavLink to="/dashboard" className={navItem}>{t('nav.today')}</NavLink>
        <NavLink to="/plan" className={navItem}>{t('nav.plan')}</NavLink>
        {isAdmin && <NavLink to="/admin" className={navItem}>{t('nav.admin')}</NavLink>}
        <NavLink to="/settings" className={navItem}>
          {t('nav.settings')}
          {pendingLinkRequests > 0 && (
            <>
              <span className="absolute right-3 top-1/2 size-2 -translate-y-1/2 rounded-full bg-[#0ea5e9]" aria-hidden="true" />
              <span className="sr-only">{t('nav.pendingLinkRequests', { n: pendingLinkRequests })}</span>
            </>
          )}
        </NavLink>
      </nav>

      <div className="mt-auto flex flex-col gap-2">
        <div className="flex min-w-0 items-center gap-2 px-1 text-sm text-muted-foreground">
          <div className="grid size-8 shrink-0 place-items-center rounded-full bg-muted font-bold text-primary">
            {(user?.email?.[0] || '?').toUpperCase()}
          </div>
          <span className="truncate">{user?.email}</span>
        </div>
        <button
          type="button"
          onClick={doLogout}
          className="cursor-pointer rounded-[10px] border-none bg-transparent px-3 py-2 text-left text-[15px] text-foreground transition-colors hover:bg-surface-hover"
        >
          {t('nav.logout')}
        </button>
      </div>
    </aside>
  );
}
