import { useToastStore } from '@/stores/toastStore';
import { cn } from '@/lib/utils';

export default function Toaster() {
  const { toasts, removeToast } = useToastStore();
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2 max-w-sm">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={cn(
            'flex items-center gap-3 rounded-md border px-4 py-3 text-sm shadow-lg animate-in slide-in-from-right-5 fade-in',
            toast.type === 'success' && 'bg-card border-success/30 text-green-400',
            toast.type === 'error' && 'bg-card border-destructive/30 text-red-400',
          )}
          onClick={() => removeToast(toast.id)}
        >
          <span className="flex-1">{toast.message}</span>
          <button className="bg-transparent border-0 text-muted-foreground hover:text-foreground cursor-pointer text-lg leading-none p-0">&times;</button>
        </div>
      ))}
    </div>
  );
}
