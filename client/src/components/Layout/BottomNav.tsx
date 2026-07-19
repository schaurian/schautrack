import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';

const icons = {
  today: <path d="M3 10.5 12 3l9 7.5V21a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z" />,
  plan: (<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="1" /></>),
  settings: (<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>),
  admin: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
};

export default function BottomNav() {
  const { t } = useTranslation('common');
  const { isAdmin, pendingLinkRequests } = useAuthStore();

  const items = [
    { to: '/dashboard', label: t('nav.today'), icon: icons.today, badge: 0 },
    { to: '/plan', label: t('nav.plan'), icon: icons.plan, badge: 0 },
    ...(isAdmin ? [{ to: '/admin', label: t('nav.admin'), icon: icons.admin, badge: 0 }] : []),
    { to: '/settings', label: t('nav.settings'), icon: icons.settings, badge: pendingLinkRequests },
  ];

  return (
    <nav className="fixed inset-x-0 bottom-0 z-50 flex border-t border-white/[0.06] bg-[#0a1120]/90 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) => cn(
            'relative flex min-h-11 flex-1 flex-col items-center justify-center gap-0.5 py-1.5 text-[10px] no-underline transition-colors',
            isActive ? 'font-bold text-primary' : 'text-muted-foreground',
          )}
        >
          <svg aria-hidden="true" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            {item.icon}
          </svg>
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
