# Mobile-Native Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** De-box the whole client UI into a native-app-feel mobile layout (bottom tabs, FAB + entry sheet, macro rings, flat lists) with a matching sidebar desktop shell.

**Architecture:** New shell primitives (BottomNav/Sidebar/Sheet/Fab/Ring/SectionLabel) + a breakpoint-switched Layout (<1024px mobile shell, ≥1024px sidebar). Existing page/domain components keep their logic and props; only their presentation is flattened. `Card` itself is restyled flat, which sweeps Settings/Plan/auth pages with minimal per-file edits.

**Tech Stack:** React 19, TypeScript, Tailwind v4 (`@theme` tokens in `client/src/styles/global.css`), react-i18next (8 locales), Vitest (pure-function tests only — no RTL), Playwright e2e via `npm run test:e2e` (docker compose).

**Spec:** `docs/superpowers/specs/2026-07-19-mobile-native-redesign-design.md`

## Global Constraints

- Working dir: `/home/schaurian/Sync/code/schautrack/.claude/worktrees/mobile-native-redesign` (branch `mobile-native-redesign`, PR target `staging`).
- Conventional commits (`feat:`/`fix:`/`refactor:`/`test:`/`docs:`). Never create version tags.
- **Every new user-facing string uses `t()`** with a key added to **all 8** locales (`client/src/i18n/locales/{en,de,es,fr,it,nl,pl,pt}/*.json`); `cd client && npm run i18n:check` must pass.
- **Do not rename existing i18n keys or aria-labels** — 60 Playwright specs select by visible text and labels.
- Desktop sidebar must render a visible `t('nav.logout')` button (e2e clicks `getByText('Logout')` at desktop viewport).
- Keep macro colors, dark palette, background gradients. No `border-2` anywhere new; hairlines only.
- Touch targets ≥44px on mobile; respect `prefers-reduced-motion` (already global via `motion-safe`/global CSS).
- Verify commands run from `client/`: `npm test` (Vitest), `npm run build` (tsc + vite), `npx eslint src` if configured via `npm run lint`.
- After UI-string changes: `npm run i18n:extract` then hand-translate new keys, then `npm run i18n:check`.

---

### Task 1: Foundation — tokens, viewport meta, media-query hook, SectionLabel, ring math

**Files:**
- Modify: `client/index.html` (viewport + theme-color)
- Modify: `client/src/styles/global.css` (divider token, sheet keyframes)
- Create: `client/src/hooks/useMediaQuery.ts`
- Create: `client/src/components/ui/SectionLabel.tsx`
- Create: `client/src/lib/ring.ts`
- Test: `client/src/lib/ring.test.ts`

**Interfaces:**
- Produces: `useIsDesktop(): boolean` (true ≥1024px); `SectionLabel({children, right?, className?})`; `ringProgress(value: number, goal: number | null): number` (0–100, 100 when no goal); `ringColor(statusClass: string, macroKey: string): string` (CSS color string).

- [ ] **Step 1: Write failing tests for ring math**

```ts
// client/src/lib/ring.test.ts
import { describe, it, expect } from 'vitest';
import { ringProgress, ringColor } from './ring';

describe('ringProgress', () => {
  it('computes percent toward goal', () => expect(ringProgress(50, 200)).toBe(25));
  it('caps at 100', () => expect(ringProgress(300, 200)).toBe(100));
  it('is 100 (full neutral ring) with no goal', () => expect(ringProgress(50, null)).toBe(100));
  it('is 100 with goal 0 (avoid div-by-zero)', () => expect(ringProgress(50, 0)).toBe(100));
  it('is 0 for zero value with goal', () => expect(ringProgress(0, 200)).toBe(0));
});

describe('ringColor', () => {
  it('maps success status to green', () => expect(ringColor('macro-stat--success', 'protein')).toBe('#22c55e'));
  it('maps warning status to amber', () => expect(ringColor('macro-stat--warning', 'kcal')).toBe('#f59e0b'));
  it('maps danger status to red', () => expect(ringColor('macro-stat--danger', 'fat')).toBe('#ef4444'));
  it('falls back to the macro color without status', () => expect(ringColor('', 'protein')).toBe('var(--color-macro-protein)'));
  it('falls back to primary for unknown macro', () => expect(ringColor('', 'nope')).toBe('var(--color-primary)'));
});
```

- [ ] **Step 2: Run to verify failure** — `cd client && npx vitest run src/lib/ring.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement**

```ts
// client/src/lib/ring.ts
// Ring math for the Today rings: percent-of-goal and status→color mapping.
// Status colors match statusClasses() in TodayPanel (green-500/amber-500/red-500 bars).

const STATUS_COLORS: Record<string, string> = {
  'macro-stat--success': '#22c55e',
  'macro-stat--warning': '#f59e0b',
  'macro-stat--danger': '#ef4444',
};

const MACRO_COLORS: Record<string, string> = {
  kcal: 'var(--color-macro-kcal)',
  protein: 'var(--color-macro-protein)',
  carbs: 'var(--color-macro-carbs)',
  fat: 'var(--color-macro-fat)',
  fiber: 'var(--color-macro-fiber)',
  sugar: 'var(--color-macro-sugar)',
};

export function ringProgress(value: number, goal: number | null): number {
  if (!goal || goal <= 0) return 100;
  return Math.min(100, Math.max(0, (value / goal) * 100));
}

export function ringColor(statusClass: string, macroKey: string): string {
  return STATUS_COLORS[statusClass] || MACRO_COLORS[macroKey] || 'var(--color-primary)';
}
```

- [ ] **Step 4: Run tests** — `npx vitest run src/lib/ring.test.ts` → PASS (10 tests).

- [ ] **Step 5: Hook + SectionLabel + tokens**

```ts
// client/src/hooks/useMediaQuery.ts
import { useSyncExternalStore } from 'react';

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const mql = window.matchMedia(query);
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    },
    () => window.matchMedia(query).matches,
  );
}

// Matches Tailwind's `lg` breakpoint — the shell switch (sidebar vs bottom tabs).
export function useIsDesktop(): boolean {
  return useMediaQuery('(min-width: 1024px)');
}
```

```tsx
// client/src/components/ui/SectionLabel.tsx
import { cn } from '@/lib/utils';

// Small uppercase section header used instead of card headers app-wide.
export function SectionLabel({ children, right, className }: {
  children: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-2 px-1 pb-1.5 pt-4', className)}>
      <h3 className="text-[11px] font-bold uppercase tracking-[0.08em] text-muted-foreground">{children}</h3>
      {right}
    </div>
  );
}
```

In `client/index.html`: change the viewport meta to `<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />` and add `<meta name="theme-color" content="#070d1a" />` next to it.

In `client/src/styles/global.css` `@theme` block, after `--color-surface-hover`, add:

```css
  --color-divider: rgba(255, 255, 255, 0.05);
```

At the end of the file (next to the `shimmer` keyframes), add:

```css
@keyframes sheet-up {
  from { transform: translateY(100%); }
  to { transform: translateY(0); }
}
```

- [ ] **Step 6: Verify + commit** — `npm test && npm run build` → all pass. Then:

```bash
git add client/index.html client/src/styles/global.css client/src/hooks/useMediaQuery.ts client/src/components/ui/SectionLabel.tsx client/src/lib/ring.ts client/src/lib/ring.test.ts
git commit -m "feat(ui): foundation for mobile-native redesign (tokens, ring math, hooks)"
```

---

### Task 2: Ring component + TodayPanel rings

**Files:**
- Create: `client/src/components/ui/Ring.tsx`
- Modify: `client/src/pages/Dashboard/TodayPanel.tsx` (full rewrite below the props interface)

**Interfaces:**
- Consumes: `ringProgress`, `ringColor` (Task 1).
- Produces: `Ring({value, goal, unit, label, macroKey, status, size?})`. TodayPanel keeps its **exact existing props** (drop-in for Dashboard.tsx).

- [ ] **Step 1: Ring component**

```tsx
// client/src/components/ui/Ring.tsx
import type { MacroStatus } from '@/types';
import { ringProgress, ringColor } from '@/lib/ring';
import { cn } from '@/lib/utils';

const LABEL_COLORS: Record<string, string> = {
  kcal: 'text-macro-kcal',
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

// Conic-gradient progress ring. Center shows the value (+ goal when set);
// ring color reflects MacroStatus (green/amber/red) falling back to the macro color.
export function Ring({ value, goal, unit, label, macroKey, status, size = 76 }: {
  value: number;
  goal: number | null;
  unit: string;
  label: string;
  macroKey: string;
  status: MacroStatus;
  size?: number;
}) {
  const pct = ringProgress(value, goal);
  const color = ringColor(status.statusClass, macroKey);
  const hole = size - 14;
  return (
    <div
      className="flex flex-col items-center"
      role="img"
      aria-label={`${label}: ${value}${goal != null ? ` / ${goal}` : ''} ${unit}`}
      title={status.statusText || undefined}
    >
      <div
        className="grid place-items-center rounded-full"
        style={{ width: size, height: size, background: `conic-gradient(${color} ${pct}%, var(--color-muted) 0)` }}
      >
        <div
          className="grid place-items-center rounded-full bg-background"
          style={{ width: hole, height: hole }}
        >
          <div className="flex flex-col items-center leading-none">
            <span className="text-[15px] font-extrabold tabular-nums">{value}</span>
            {goal != null && (
              <span className="mt-0.5 text-[9px] text-muted-foreground tabular-nums">/{goal}{unit !== 'kcal' ? unit : ''}</span>
            )}
          </div>
        </div>
      </div>
      <span className={cn('mt-1.5 text-[10px] font-bold uppercase tracking-wider', LABEL_COLORS[macroKey] || 'text-primary')}>
        {label}
      </span>
    </div>
  );
}
```

- [ ] **Step 2: Rewrite TodayPanel body**

Keep imports of `MacroStatus`, `MACRO_LABELS`/`MacroKey`, `useTranslation`, and the `Props` interface and empty-state exactly as they are. Replace everything from `const itemCount…` and the returned `<section>` (and delete the now-unused `MacroChip`, `statusClasses`, `LABEL_COLORS`, `BAR_COLORS` definitions) with:

```tsx
  return (
    <section className="flex flex-wrap items-start justify-center gap-x-5 gap-y-4 py-2">
      {caloriesEnabled && (
        <Ring
          macroKey="kcal"
          label={t('entries.caloriesLabel')}
          value={todayTotal}
          goal={dailyGoal}
          unit="kcal"
          status={calorieStatus}
        />
      )}
      {enabledMacros.map((key) => (
        <Ring
          key={key}
          macroKey={key}
          label={MACRO_LABELS[key as MacroKey]?.label || key}
          value={todayMacroTotals[key] || 0}
          goal={macroGoals[key] ?? null}
          unit="g"
          status={macroStatuses[key] || { statusClass: '', statusText: '' }}
        />
      ))}
    </section>
  );
```

Add `import { Ring } from '@/components/ui/Ring';`. The `selectedDate`/`todayStr` props stay accepted (Dashboard header takes over the date display in Task 6) — prefix them with `_` if the linter complains, but do not change the `Props` interface.

- [ ] **Step 3: Verify + commit** — `npm test && npm run build` → PASS.

```bash
git add client/src/components/ui/Ring.tsx client/src/pages/Dashboard/TodayPanel.tsx
git commit -m "feat(dashboard): replace Today stat tiles with macro progress rings"
```

---

### Task 3: Sheet + Fab primitives

**Files:**
- Create: `client/src/components/ui/Sheet.tsx`
- Create: `client/src/components/ui/Fab.tsx`

**Interfaces:**
- Produces: `Sheet({open, onClose, title?, children})` — bottom sheet <lg, centered dialog ≥lg; portal; Escape/backdrop close; scroll-lock; focus restore. `Fab({onClick, 'aria-label', children?})` — fixed bottom-right above the tab bar, `lg:hidden`.

- [ ] **Step 1: Implement Sheet**

```tsx
// client/src/components/ui/Sheet.tsx
import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { cn } from '@/lib/utils';

// Bottom sheet on mobile, centered dialog on desktop. Children keep their
// state across open/close only if the parent keeps them mounted; Sheet itself
// unmounts its subtree when closed.
export function Sheet({ open, onClose, title, children }: {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    panelRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKey);
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[200]">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          'absolute inset-x-0 bottom-0 max-h-[85dvh] overflow-y-auto rounded-t-[20px] border-t border-border bg-[#0e1626] p-4 pb-[calc(1rem+env(safe-area-inset-bottom))] outline-none',
          'motion-safe:animate-[sheet-up_0.25s_ease-out]',
          'lg:inset-x-auto lg:bottom-auto lg:left-1/2 lg:top-1/2 lg:w-full lg:max-w-md lg:-translate-x-1/2 lg:-translate-y-1/2 lg:rounded-2xl lg:border lg:pb-4 lg:motion-safe:animate-none',
        )}
      >
        <div className="mx-auto mb-3 h-1 w-9 rounded-full bg-border lg:hidden" aria-hidden="true" />
        {title && <h2 className="mb-3 text-base font-bold">{title}</h2>}
        {children}
      </div>
    </div>,
    document.body,
  );
}
```

- [ ] **Step 2: Implement Fab**

```tsx
// client/src/components/ui/Fab.tsx
import { cn } from '@/lib/utils';

// Floating action button — mobile only, sits above the bottom tab bar.
export function Fab({ onClick, className, 'aria-label': ariaLabel }: {
  onClick: () => void;
  className?: string;
  'aria-label': string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
      className={cn(
        'fixed bottom-[calc(4.5rem+env(safe-area-inset-bottom))] right-4 z-[60] grid size-14 cursor-pointer place-items-center rounded-2xl',
        'bg-gradient-to-br from-secondary to-primary text-primary-foreground shadow-[0_6px_24px_rgba(109,140,255,0.45)]',
        'transition-transform active:scale-95 lg:hidden',
        className,
      )}
    >
      <svg aria-hidden="true" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
        <path d="M12 5v14" /><path d="M5 12h14" />
      </svg>
    </button>
  );
}
```

- [ ] **Step 3: Verify + commit** — `npm run build` → PASS (components are wired in Tasks 4/6).

```bash
git add client/src/components/ui/Sheet.tsx client/src/components/ui/Fab.tsx
git commit -m "feat(ui): Sheet and Fab primitives for the mobile shell"
```

---

### Task 4: App shell — BottomNav, Sidebar, new Layout, slim Header

**Files:**
- Create: `client/src/components/Layout/BottomNav.tsx`
- Create: `client/src/components/Layout/Sidebar.tsx`
- Modify: `client/src/components/Layout/Layout.tsx`
- Modify: `client/src/components/Layout/Header.tsx` (guest-only; delete the authed branch)
- Modify: `client/src/i18n/locales/*/common.json` ×8 (add `nav.today`)
- Modify: `e2e/navigation.spec.ts`, `e2e/mobile.spec.ts`

**Interfaces:**
- Consumes: `useAuthStore` (`user`, `isAdmin`, `pendingLinkRequests`, `clearUser`), `logout` from `@/api/auth`, `useDashboardStore().reset()`.
- Produces: authed shell = `Sidebar` (≥lg) + centered `<main>` + `BottomNav` (<lg). A shared `useLogout()` helper exported from `Sidebar.tsx` is NOT created — logout logic lives once in `client/src/hooks/useLogout.ts` (below) and is reused by Settings in Task 5.

- [ ] **Step 1: Shared logout hook** — move `handleLogout` out of Header:

```ts
// client/src/hooks/useLogout.ts
import { useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '@/stores/authStore';
import { useDashboardStore } from '@/stores/dashboardStore';
import { logout } from '@/api/auth';

// 1. Network logout, then 2. clear all client state so the previous
// account's data can't leak into the next login in this tab, then 3. navigate.
export function useLogout() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const clearUser = useAuthStore((s) => s.clearUser);
  return async () => {
    try { await logout(); } catch { /* ignore */ }
    queryClient.clear();
    useDashboardStore.getState().reset();
    clearUser();
    navigate('/login');
  };
}
```

- [ ] **Step 2: BottomNav**

```tsx
// client/src/components/Layout/BottomNav.tsx
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
    <nav className="fixed inset-x-0 bottom-0 z-50 flex border-t border-border bg-[#0a1120]/95 pb-[env(safe-area-inset-bottom)] backdrop-blur lg:hidden">
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
```

- [ ] **Step 3: Sidebar**

```tsx
// client/src/components/Layout/Sidebar.tsx
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
          <span className="text-[16px] font-bold tracking-tight">{t('app.name')}</span>
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
```

- [ ] **Step 4: New Layout**

```tsx
// client/src/components/Layout/Layout.tsx
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
```

- [ ] **Step 5: Slim Header** — in `Header.tsx`, delete the entire `user ? (…) : (…)` authed branch (hamburger button, `#mobile-nav` nav, backdrop, `handleLogout`, `navClass`, the `menuOpen` state/effect, and now-unused imports `useState`, `useEffect`, `useNavigate`, `useQueryClient`, `useDashboardStore`, `logout`, `cn`, `useLocation`). Keep the logo link (`to={user ? '/dashboard' : '/'}` still reads `user` from the store) and the guest `Login`/`Register` nav; when `user` is set render `null` in place of the guest nav (belt-and-braces — authed Layout no longer mounts Header).

- [ ] **Step 6: i18n `nav.today`** — in all 8 `client/src/i18n/locales/<lng>/common.json`, add inside `"nav"`: en `"today": "Today"`, de `"Heute"`, es `"Hoy"`, fr `"Aujourd'hui"`, it `"Oggi"`, nl `"Vandaag"`, pl `"Dzisiaj"`, pt `"Hoje"`. Run `npm run i18n:check` → PASS.

- [ ] **Step 7: Update e2e** — `e2e/navigation.spec.ts`: the authed nav test clicks `getByText('Settings')` then `getByText('Dashboard')` — change the second to `page.getByText('Today', { exact: true }).click()` (sidebar label changed). `e2e/mobile.spec.ts`: read it; replace any hamburger-menu interactions (`aria-label` toggle menu) with tab-bar navigation (`page.getByRole('link', { name: 'Settings' })` inside `nav`), keep its other assertions.

- [ ] **Step 8: Verify + commit** — `npm test && npm run build && npm run i18n:check` → PASS. Manual smoke: `npm run dev` and check shell at 375px and 1280px widths (sidebar left, tabs bottom, logout visible on desktop).

```bash
git add client/src e2e/navigation.spec.ts e2e/mobile.spec.ts
git commit -m "feat(shell): bottom tab bar + desktop sidebar replace the header nav"
```

---

### Task 5: Logout row in Settings

**Files:**
- Modify: `client/src/pages/Settings/Settings.tsx`
- Modify: `client/src/i18n/locales/*/settings.json` ×8 (only if no suitable existing key — reuse `common:nav.logout` for the label)

**Interfaces:**
- Consumes: `useLogout()` (Task 4).

- [ ] **Step 1:** In `Settings.tsx`, import `useLogout` and `useTranslation('common')` alongside the existing translation hook, and render at the **top** of the settings stack (before the first section):

```tsx
<div className="flex items-center justify-between border-b border-divider pb-4">
  <span className="min-w-0 truncate text-sm text-muted-foreground">{user?.email}</span>
  <button
    type="button"
    onClick={doLogout}
    className="cursor-pointer rounded-[10px] border border-border bg-transparent px-3.5 py-2 text-sm text-foreground transition-colors hover:bg-surface-hover"
  >
    {tCommon('nav.logout')}
  </button>
</div>
```

(`user` comes from the auth store the page already reads; if it doesn't, add `const user = useAuthStore((s) => s.user);`.)

- [ ] **Step 2: Verify + commit** — `npm run build`; `npm run dev`, confirm logout works from Settings on a 375px viewport (returns to /login).

```bash
git add client/src/pages/Settings/Settings.tsx
git commit -m "feat(settings): logout row (mobile shell has no header logout)"
```

---

### Task 6: Dashboard header + FAB/Sheet entry flow + flat inline form

**Files:**
- Modify: `client/src/pages/Dashboard/Dashboard.tsx`
- Modify: `client/src/pages/Dashboard/EntryForm.tsx` (remove card wrapper only)
- Modify: `client/src/i18n/locales/*/dashboard.json` ×8 (add `entries.addFood`)

**Interfaces:**
- Consumes: `Sheet`, `Fab`, `useIsDesktop`, `SectionLabel`.
- Produces: EntryForm without outer card (pure form) — same props, plus existing `onSubmit` used to close the sheet.

- [ ] **Step 1: De-box EntryForm** — in `EntryForm.tsx`, replace the outer wrapper. Delete the card `<div className="rounded-xl border-2 …">` and its header `<div className="px-4 py-3 border-b-2 …"><h3>…logSectionTitle…</h3></div>`; the component's root becomes `<form onSubmit={handleSubmit} className="flex flex-col">` (drop the `p-4`; keep everything inside — fields, modals, Suspense — unchanged, the two modal blocks move inside a fragment `<>…</>` root wrapping form + modals).

- [ ] **Step 2: Dashboard wiring** — in `Dashboard.tsx`:
  - Add imports: `useState`, `Sheet`, `Fab`, `SectionLabel`, `useIsDesktop`, and `useTranslation('dashboard')` if not present (it is — `t` is already used).
  - Add state `const [addOpen, setAddOpen] = useState(false);` and `const isDesktop = useIsDesktop();`.
  - Add a page header as the first child of the returned column, replacing TodayPanel's old internal title:

```tsx
<header className="flex items-baseline justify-between px-1 pt-1">
  <h2 className="text-[22px] font-extrabold tracking-tight">
    {selectedDate === dashboard.todayStr ? t('dashboard.todayLabel') : selectedDate}
  </h2>
  <input
    type="date"
    aria-label={t('entries.entryDateAriaLabel')}
    className="rounded-md border border-input bg-muted/50 px-2 py-1 text-sm text-foreground outline-none focus:border-ring"
    value={selectedDate}
    onChange={(e) => e.target.value && selectDay(e.target.value)}
  />
</header>
```

  - Replace the `{canEdit && (<><SavedFoodsRow …/><EntryForm …/></>)}` block with:

```tsx
{canEdit && (isDesktop ? (
  <section>
    <SectionLabel>{t('entries.logSectionTitle')}</SectionLabel>
    <SavedFoodsRow selectedDate={selectedDate} />
    <EntryForm {…same props as before…} />
  </section>
) : (
  <>
    <Fab aria-label={t('entries.addFood')} onClick={() => setAddOpen(true)} />
    <Sheet open={addOpen} onClose={() => setAddOpen(false)} title={t('entries.addFood')}>
      <SavedFoodsRow selectedDate={selectedDate} />
      <EntryForm
        {…same props…}
        onSubmit={() => setAddOpen(false)}
      />
    </Sheet>
  </>
))}
```

  (`{…same props…}` = the exact prop list currently passed, spelled out — `selectedDate`, `caloriesEnabled`, `autoCalcCalories`, `enabledMacros`, `hasAiEnabled`, `aiUsage`, `aiProviderName`, `barcodeEnabled`; desktop `onSubmit` keeps the current no-op-with-comment.)

- [ ] **Step 3: i18n `entries.addFood`** — add to all 8 `dashboard.json` under `entries`: en `"addFood": "Add food"`, de `"Essen hinzufügen"`, es `"Añadir comida"`, fr `"Ajouter un aliment"`, it `"Aggiungi cibo"`, nl `"Voeding toevoegen"`, pl `"Dodaj posiłek"`, pt `"Adicionar alimento"`.

- [ ] **Step 4: Verify + commit** — `npm test && npm run build && npm run i18n:check`; `npm run dev`: at 375px the FAB opens the sheet, tracking an entry closes it and the entry appears; at 1280px the inline form works as before.

```bash
git add client/src/pages/Dashboard/Dashboard.tsx client/src/pages/Dashboard/EntryForm.tsx client/src/i18n/locales
git commit -m "feat(dashboard): FAB + bottom-sheet entry flow on mobile, flat inline form on desktop"
```

---

### Task 7: Flat entry list + compact MacroPill

**Files:**
- Modify: `client/src/pages/Dashboard/Dashboard.tsx` (entries card → section)
- Modify: `client/src/pages/Dashboard/EntryList.tsx`
- Modify: `client/src/components/ui/MacroPill.tsx`

- [ ] **Step 1: Section wrapper** — in `Dashboard.tsx`, replace the entries card:

```tsx
{showCat('nutrition') && (
  <section>
    <SectionLabel right={<span className="text-xs text-muted-foreground">{t('dashboard.entriesDateAndLabel', { date: selectedDate, label: currentLabel })}</span>}>
      {t('dashboard.entriesSectionTitle')}
    </SectionLabel>
    <EntryList … same props … />
  </section>
)}
```

- [ ] **Step 2: Flat rows** — in `EntryList.tsx`: list wrapper `<div className="flex flex-col gap-1.5 p-2">` → `<div className="flex flex-col divide-y divide-divider">`. In `EntryRow`, the outer `<div className={cn('rounded-[10px] border border-border bg-white/[0.015] …')}>` → `<div className={cn('py-0.5 transition-colors', editing && 'rounded-[10px] bg-[#0ea5e9]/5')}>`. Row paddings: name row `px-3 py-2` → `px-1 py-2`; pills row `px-3 pb-2.5` → `px-1 pb-2`.

- [ ] **Step 3: Compact pills** — in `MacroPill.tsx` display variant, change the button classes `'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-sm tabular-nums transition-colors'` → `'inline-flex min-h-6 items-center gap-1 rounded-md border border-transparent px-1.5 py-0.5 text-sm tabular-nums transition-colors'` and drop `style.bg`/`style.border` from the display variant (keep `style.label` for the label color; keep the editing variant's classes unchanged so the edit affordance stays visible). Interactive hover becomes `hover:bg-white/[0.06]`.

- [ ] **Step 4: Verify + commit** — `npm test && npm run build`; dev-check both viewports (tap-to-edit still works, delete/undo toast, save-as-quick-add).

```bash
git add client/src/pages/Dashboard/Dashboard.tsx client/src/pages/Dashboard/EntryList.tsx client/src/components/ui/MacroPill.tsx
git commit -m "refactor(dashboard): flat divider entry rows with compact macro values"
```

---

### Task 8: Flat timeline

**Files:**
- Modify: `client/src/pages/Dashboard/Timeline.tsx`
- Modify: `client/src/pages/Dashboard/ShareCard.tsx`

- [ ] **Step 1: Timeline de-box** — in `Timeline.tsx`, replace the outer card + header with a section + `SectionLabel`; move the range presets behind a compact toggle:

```tsx
const [showRanges, setShowRanges] = useState(false);
…
return (
  <section>
    <SectionLabel
      right={
        <button
          type="button"
          className="cursor-pointer rounded-md border border-transparent bg-transparent px-2 py-1 text-xs font-bold text-primary transition-colors hover:bg-surface-hover"
          onClick={() => setShowRanges(!showRanges)}
          aria-expanded={showRanges}
        >
          {t('dashboard.rangeDays', { count: range.days })} ▾
        </button>
      }
    >
      {t('dashboard.timelineTitle')}
    </SectionLabel>
    {showRanges && (
      <div className="flex flex-wrap gap-1.5 px-1 pb-3">
        …existing preset buttons + custom toggle, unchanged classes…
      </div>
    )}
    {showCustom && ( …existing custom-range block, `mx-4 mb-4` → `mx-1 mb-3`… )}
    <div className="flex flex-col gap-4 px-1">
      {sharedViews.map(…ShareCard as before…)}
    </div>
  </section>
);
```

  Preset clicks keep working unchanged; after choosing a preset also `setShowRanges(false)`.

- [ ] **Step 2: Flat ShareCard** — in `ShareCard.tsx` (read it fully first), remove its card border/background wrapper classes (`rounded-*, border*, bg-card/…`) in favor of a plain block: label row (small uppercase, keep the edit-pencil and selection behavior/aria) + the DayDot grid. **Do not change**: selection `onSelect` target's role/labels, dot click wiring, label-edit input logic — the link-sharing e2e specs click these.

- [ ] **Step 3: Verify + commit** — `npm test && npm run build`; dev-check: preset popover works, day dots select days, friend card selectable, label editing intact.

```bash
git add client/src/pages/Dashboard/Timeline.tsx client/src/pages/Dashboard/ShareCard.tsx
git commit -m "refactor(dashboard): flat edge-to-edge timeline with compact range picker"
```

---

### Task 9: Flat weight, todos, notes, plan-link sections

**Files:**
- Modify: `client/src/pages/Dashboard/WeightRow.tsx`
- Modify: `client/src/pages/Dashboard/TodoList.tsx`
- Modify: `client/src/pages/Dashboard/NoteEditor.tsx`
- Modify: `client/src/pages/Dashboard/PlanCard.tsx`

- [ ] **Step 1:** Read each file; apply the same transformation as Task 7/8: outer `rounded-xl border-2 border-border bg-card` wrappers → `<section>`; internal `px-4 py-3 border-b-2` headers → `SectionLabel` (reusing each file's existing title `t()` key, with any header-right content passed as `right=`); inner list items → `divide-y divide-divider` rows with `px-1` gutters; keep every input, checkbox, button, aria-label, and handler untouched.
- [ ] **Step 2:** `PlanCard.tsx` specifically: keep it a `<Link>`; classes → `'block px-1 py-3 no-underline text-foreground'` with the trend chip and progress bar unchanged, plus a `SectionLabel` above (`plan` title key it already uses) — the whole thing wrapped in a `<section>`.
- [ ] **Step 3: Verify + commit** — `npm test && npm run build`; dev-check all four sections at both viewports (todo add/check/delete, weight tap-to-edit, note save, plan link navigates).

```bash
git add client/src/pages/Dashboard/WeightRow.tsx client/src/pages/Dashboard/TodoList.tsx client/src/pages/Dashboard/NoteEditor.tsx client/src/pages/Dashboard/PlanCard.tsx
git commit -m "refactor(dashboard): flatten weight, todos, notes and plan sections"
```

---

### Task 10: Flatten Card primitive → Settings/Plan/auth sweep

**Files:**
- Modify: `client/src/components/ui/Card.tsx`
- Modify (visual pass, spacing only where needed): `client/src/pages/Settings/*.tsx`, `client/src/pages/Plan/*.tsx`, `client/src/pages/Login/Login.tsx`, `client/src/pages/Register/Register.tsx`, `client/src/pages/ForgotPassword/ForgotPassword.tsx`, `client/src/pages/ResetPassword/ResetPassword.tsx`, `client/src/pages/VerifyEmail/VerifyEmail.tsx`, `client/src/pages/VerifyEmailChange/VerifyEmailChange.tsx`, `client/src/pages/Delete/DeleteAccount.tsx`, `client/src/pages/Legal/*.tsx`

- [ ] **Step 1: Restyle Card** — in `Card.tsx`:

```tsx
const Card = … className={cn('border-b border-divider py-6 first:pt-2 last:border-0 text-card-foreground', className)} …
const CardHeader = … className={cn('flex flex-col space-y-1.5 pb-4', className)} …   // unchanged
const CardTitle = … className={cn('text-[11px] font-bold uppercase tracking-[0.08em] text-muted-foreground leading-none', className)} …
```

  (`CardContent` unchanged.) This flattens every consumer in one move.

- [ ] **Step 2: Auth-page panel exception** — Login/Register/ForgotPassword/ResetPassword center a form; after flattening, give each page's Card a contained look via className override where it reads better on desktop: `className="rounded-2xl border border-border bg-card/60 p-6 lg:p-8 border-b"` (they pass className already or accept one). Check each of the four pages in the dev server and apply only where the flat look loses the form's focus.
- [ ] **Step 3: Visual pass** — `npm run dev`; walk Settings (all 14 sections incl. 2FA/passkeys flows collapsed states), Plan, Delete, Legal, Verify pages at 375px and 1280px. Fix only spacing/margin artifacts caused by the Card change (e.g. doubled padding wrappers), never logic. Keep the Delete page's destructive red accents.
- [ ] **Step 4: Verify + commit** — `npm test && npm run build`.

```bash
git add client/src/components/ui/Card.tsx client/src/pages
git commit -m "refactor(ui): flatten Card primitive — de-box settings, plan and auth pages"
```

---

### Task 11: Admin pass

**Files:**
- Modify: `client/src/pages/Admin/*.tsx` (spacing/width only — Card flattening from Task 10 already applies)

- [ ] **Step 1:** `npm run dev`, open `/admin` (dev compose provides an admin user; otherwise run the e2e stack `npm run test:e2e:setup` and use its admin). Fix table overflow: any `<table>` gets a wrapping `<div className="overflow-x-auto">` if missing; check the wide Layout column (Task 4 set `/admin` → `max-w-[1000px]`) renders tables un-cramped at 1280px and scrollable at 375px.
- [ ] **Step 2: Verify + commit** — `npm test && npm run build`.

```bash
git add client/src/pages/Admin
git commit -m "refactor(admin): flat layout polish and mobile table overflow"
```

---

### Task 12: i18n extraction + parity

**Files:**
- Modify: `client/src/i18n/locales/**` (whatever `i18n:extract` surfaces)

- [ ] **Step 1:** `cd client && npm run i18n:extract` — inspect `git diff`: any key the extractor adds beyond `nav.today`/`entries.addFood` means a string slipped in untranslated; give it a proper key + translations in all 8 locales (translate faithfully, no machine-English placeholders).
- [ ] **Step 2:** `npm run i18n:check` → PASS. `npm test && npm run build` → PASS.
- [ ] **Step 3: Commit**

```bash
git add client/src/i18n
git commit -m "chore(i18n): extract + translate redesign strings across 8 locales"
```

---

### Task 13: E2E + mobile spec + final verification

**Files:**
- Create: `e2e/mobile-shell.spec.ts`
- Modify: whatever the triage below identifies (expected: `e2e/timeline.spec.ts`, `e2e/share-card.spec.ts`, `e2e/entry-cards.spec.ts`, `e2e/settings.spec.ts` — selector-level only)

- [ ] **Step 1: New mobile-shell spec**

```ts
// e2e/mobile-shell.spec.ts
import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.use({ viewport: { width: 390, height: 844 } });

test.describe('Mobile shell', () => {
  test('bottom tabs navigate', async ({ page }) => {
    await login(page);
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings/);
    await page.getByRole('link', { name: 'Today' }).click();
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('FAB opens sheet and tracks an entry', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();
    await dialog.getByPlaceholder('Breakfast, snack...').fill('Sheet test food');
    await dialog.getByLabel('Calories').fill('123');
    await dialog.getByRole('button', { name: 'Track' }).click();
    await expect(dialog).not.toBeVisible();
    await expect(page.getByText('Sheet test food')).toBeVisible();
  });

  test('logout from settings', async ({ page }) => {
    await login(page);
    await page.getByRole('link', { name: 'Settings' }).click();
    await page.getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/login/);
  });
});
```

  Adjust the two field selectors to the real accessible names from `EntryForm.tsx` (`entries.foodNamePlaceholder` / `entries.caloriesLabel` — English test locale).

- [ ] **Step 2: Full run** — from repo root: `npm run test:e2e` (needs Docker; ~all 60 specs + new one). Expect failures ONLY in specs touching removed chrome. Triage rule: fix the **selector**, never weaken an assertion; if a behavior genuinely changed (header nav → sidebar/tabs, entries card → section), update the spec to assert the new structure's equivalent behavior.
- [ ] **Step 3:** Re-run failed specs until green: `npx playwright test <spec> --project=chromium` against the still-running stack (`npm run test:e2e:setup` to boot it without the full run).
- [ ] **Step 4: Visual evidence** — with the test stack up, capture screenshots for the PR: `npx playwright screenshot --viewport-size=390,844 http://localhost:<port>/dashboard shots/mobile-dashboard.png` (log in via storage state from the e2e fixtures — or add a tiny throwaway spec that saves screenshots to `playwright-report/`). Attach mobile + desktop dashboard shots to the PR description.
- [ ] **Step 5: Final gates** — `cd client && npm test && npm run build && npm run i18n:check`; repo root `go test ./...` (must stay green — no backend changes). Commit any spec fixes:

```bash
git add e2e
git commit -m "test(e2e): mobile shell spec + selector updates for the redesign"
```

---

## Self-review notes

- Spec §3 nav/shell → Tasks 4–5. §4 Today/rings/timeline/lists → Tasks 2, 6–9. §4 add-food sheet/inline → Task 6. §4 Plan/Settings/Admin/auth → Tasks 10–11. §5 primitives → Tasks 1–3. §6 tokens/Android meta → Task 1. §7 i18n → Tasks 4, 6, 12. §9 testing → every task + Task 13. §10 phases map to task order.
- **Deviations from spec (deliberate, lower-risk):** desktop entry form stays fully visible (no collapse-on-focus) to keep 8 entry-form specs valid; timeline keeps per-user dot sections (flattened ShareCard) instead of replacing them with switcher chips — same behaviors, less e2e churn; AI/barcode/saved-foods modals keep their current overlay presentation (Sheet adoption is a follow-up). Spec file is amended alongside this plan.
