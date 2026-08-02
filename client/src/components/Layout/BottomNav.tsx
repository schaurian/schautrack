import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';
import { NavIcon, type NavIconName } from './navIcons';

export default function BottomNav() {
  const { t } = useTranslation('common');
  const { isAdmin, pendingLinkRequests } = useAuthStore();

  // Same destinations and same icons as the desktop Sidebar (both read from
  // navIcons), but deliberately in the reverse order: Account · Settings ·
  // Admin · Plan · Today. Thumbs rest on the right of a phone, so the tab you
  // open most often sits furthest from the reach — this is an explicit product
  // choice, not drift. The sidebar keeps reading top-down Today → Account.
  const items: { to: string; label: string; icon: NavIconName; badge: number }[] = [
    { to: '/account', label: t('nav.account'), icon: 'account', badge: 0 },
    { to: '/settings', label: t('nav.settings'), icon: 'settings', badge: pendingLinkRequests },
    ...(isAdmin ? [{ to: '/admin', label: t('nav.admin'), icon: 'admin' as NavIconName, badge: 0 }] : []),
    { to: '/plan', label: t('nav.plan'), icon: 'plan', badge: 0 },
    { to: '/dashboard', label: t('nav.today'), icon: 'today', badge: 0 },
  ];

  return (
    <nav className="fixed inset-x-0 bottom-0 z-50 flex border-t border-white/[0.06] bg-[#0d1226]/92 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) => cn(
            'relative flex min-h-11 flex-1 flex-col items-center justify-center gap-0.5 py-1.5 font-display text-[10px] no-underline transition-colors',
            isActive ? 'font-bold text-primary' : 'text-muted-foreground',
          )}
        >
          <NavIcon name={item.icon} size={22} />
          {item.label}
          {item.badge > 0 && (
            <>
              <span className="absolute right-[calc(50%-16px)] top-1 size-2 rounded-full bg-[#0ea5e9]" aria-hidden="true" />
              <span className="sr-only">{t('nav.pendingLinkRequests', { n: item.badge })}</span>
            </>
          )}
        </NavLink>
      ))}
    </nav>
  );
}
