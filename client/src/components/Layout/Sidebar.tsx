import { useTranslation } from 'react-i18next';
import { Link, NavLink } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';
import { NavIcon } from './navIcons';

export default function Sidebar() {
  const { t } = useTranslation('common');
  const { isAdmin, pendingLinkRequests } = useAuthStore();

  const navItem = ({ isActive }: { isActive: boolean }) => cn(
    'relative flex items-center gap-2.5 rounded-[10px] px-3 py-2 text-[15px] no-underline transition-colors',
    isActive ? 'bg-primary/12 font-semibold text-primary' : 'text-foreground hover:bg-surface-hover',
  );

  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-[220px] flex-col border-r border-divider bg-[#0b1124]/70 p-4 lg:flex">
      <Link to="/dashboard" className="mb-6 flex items-center gap-2.5 text-foreground no-underline">
        <div className="grid size-10 shrink-0 place-items-center overflow-hidden rounded-[10px] border border-border bg-card">
          <img src="/logo-128.webp" alt="" width={40} height={40} decoding="async" className="block h-full w-full object-cover" />
        </div>
        <div className="flex flex-col leading-none">
          <span className="font-display text-[16px] font-bold tracking-tight">{t('app.name')}</span>
          <span className="text-[12px] text-muted-foreground">{t('header.tagline')}</span>
        </div>
      </Link>

      {/* Same destinations, same order, same glyphs as the mobile BottomNav —
          both render from navIcons. Desktop keeps the labels alongside. */}
      <nav className="flex flex-col gap-1">
        <NavLink to="/dashboard" className={navItem}><NavIcon name="today" size={18} />{t('nav.today')}</NavLink>
        <NavLink to="/plan" className={navItem}><NavIcon name="plan" size={18} />{t('nav.plan')}</NavLink>
        {isAdmin && <NavLink to="/admin" className={navItem}><NavIcon name="admin" size={18} />{t('nav.admin')}</NavLink>}
        <NavLink to="/settings" className={navItem}>
          <NavIcon name="settings" size={18} />
          {t('nav.settings')}
          {pendingLinkRequests > 0 && (
            <>
              <span className="absolute right-3 top-1/2 size-2 -translate-y-1/2 rounded-full bg-[#0ea5e9]" aria-hidden="true" />
              <span className="sr-only">{t('nav.pendingLinkRequests', { n: pendingLinkRequests })}</span>
            </>
          )}
        </NavLink>
        <NavLink to="/account" className={navItem}><NavIcon name="account" size={18} />{t('nav.account')}</NavLink>
      </nav>

      {/* Deliberately no user block at the bottom: /account is a labelled nav
          item above, so an avatar row pointing at the same route would be a
          second link to one destination inside a 220px column. The email is
          shown on /account itself, and logout lives there too — it is no longer
          a sidebar button here plus an lg:hidden row in Settings on mobile. */}
    </aside>
  );
}
