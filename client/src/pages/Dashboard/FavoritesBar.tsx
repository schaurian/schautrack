import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { applyTemplate, listTemplates } from '@/api/templates';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  selectedDate: string;
  canEdit: boolean;
}

export default function FavoritesBar({ selectedDate, canEdit }: Props) {
  const addToast = useToastStore((s) => s.addToast);
  const queryClient = useQueryClient();
  const [pendingId, setPendingId] = useState<number | null>(null);

  const { data } = useQuery({
    queryKey: ['templates'],
    queryFn: () => listTemplates(false),
    enabled: canEdit,
  });

  const applyMutation = useMutation({
    mutationFn: (id: number) => applyTemplate(id, selectedDate),
    onMutate: (id) => setPendingId(id),
    onSettled: () => setPendingId(null),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['day-entries'] });
      addToast('success', `Added ${res.count} entr${res.count === 1 ? 'y' : 'ies'}`);
    },
    onError: (err: Error) => addToast('error', err.message || 'Failed to apply'),
  });

  if (!canEdit) return null;

  const favorites = (data?.templates ?? []).filter((t) => t.is_favorite);
  const hasTemplates = (data?.templates ?? []).length > 0;

  // If there are no templates at all, don't render the bar (avoid noise on empty setups).
  if (!hasTemplates) return null;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-2 border-b-2 border-border flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Quick add</h3>
        <Link to="/templates" className="text-xs text-muted-foreground hover:text-foreground">
          Manage
        </Link>
      </div>
      <div className="px-4 py-3 flex flex-wrap gap-2">
        {favorites.length === 0 ? (
          <span className="text-xs text-muted-foreground">
            Star a template to pin it here.
          </span>
        ) : (
          favorites.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => applyMutation.mutate(t.id)}
              disabled={pendingId === t.id || !selectedDate}
              title={`Add ${t.items.length} entr${t.items.length === 1 ? 'y' : 'ies'} to ${selectedDate}`}
              className="inline-flex items-center gap-1.5 rounded-full border border-[#f59e0b]/40 bg-[#f59e0b]/[0.07] px-3 py-1 text-xs text-foreground hover:bg-[#f59e0b]/[0.13] hover:border-[#f59e0b]/70 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-colors"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="#f59e0b" stroke="#f59e0b" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
              </svg>
              <span className="truncate max-w-[160px]">{t.name}</span>
              {pendingId === t.id && <span className="text-muted-foreground">…</span>}
            </button>
          ))
        )}
      </div>
    </div>
  );
}
