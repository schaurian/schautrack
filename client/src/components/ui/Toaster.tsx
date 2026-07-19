import { useTranslation } from 'react-i18next';
import { useToastStore } from '@/stores/toastStore';
import { cn } from '@/lib/utils';

export default function Toaster() {
  const { t } = useTranslation('common');
  const { toasts, removeToast, pauseToast, resumeToast } = useToastStore();

  // The live-region container is always rendered so screen readers observe it
  // before toasts are inserted. Non-error toasts inherit polite; error toasts
  // override to an assertive alert.
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="false"
      className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2 max-w-sm"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role={toast.type === 'error' ? 'alert' : undefined}
          aria-live={toast.type === 'error' ? 'assertive' : undefined}
          onMouseEnter={() => pauseToast(toast.id)}
          onMouseLeave={() => resumeToast(toast.id)}
          onFocus={() => pauseToast(toast.id)}
          onBlur={() => resumeToast(toast.id)}
          className={cn(
            'flex items-center gap-3 rounded-md border px-4 py-3 text-sm shadow-lg animate-in slide-in-from-right-5 fade-in',
            toast.type === 'success' && 'bg-card border-success/30 text-green-400',
            toast.type === 'error' && 'bg-card border-destructive/30 text-red-400',
            toast.type === 'info' && 'bg-card border-[#0ea5e9]/30 text-[#0ea5e9]',
          )}
        >
          <span className="flex-1">{toast.message}</span>
          {toast.action && (
            <button
              type="button"
              className="bg-transparent border border-current/50 rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:bg-current/10 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                toast.action!.onClick();
                removeToast(toast.id);
              }}
            >
              {toast.action.label}
            </button>
          )}
          <button
            type="button"
            aria-label={t('toaster.dismiss')}
            className="bg-transparent border-0 text-muted-foreground hover:text-foreground cursor-pointer text-lg leading-none p-0"
            onClick={() => removeToast(toast.id)}
          >&times;</button>
        </div>
      ))}
    </div>
  );
}
