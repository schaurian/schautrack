import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import {
  applyTemplate,
  deleteTemplate,
  listTemplates,
  toggleTemplateFavorite,
} from '@/api/templates';
import { useDashboardStore } from '@/stores/dashboardStore';
import { useToastStore } from '@/stores/toastStore';
import { Button } from '@/components/ui/Button';
import type { MealTemplate } from '@/types';
import TemplateEditor from './TemplateEditor';

export default function Templates() {
  const { user, isLoading: authLoading } = useRequireAuth();
  const addToast = useToastStore((s) => s.addToast);
  const selectedDate = useDashboardStore((s) => s.selectedDate);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['templates'],
    queryFn: () => listTemplates(false),
    enabled: !!user,
  });

  const [editing, setEditing] = useState<MealTemplate | null>(null);
  const [creatingNew, setCreatingNew] = useState(false);
  const [pendingId, setPendingId] = useState<number | null>(null);

  const favoriteMutation = useMutation({
    mutationFn: (t: MealTemplate) => toggleTemplateFavorite(t.id, !t.is_favorite),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['templates'] }),
    onError: (err: Error) => addToast('error', err.message || 'Failed to update'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteTemplate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      addToast('success', 'Template deleted');
    },
    onError: (err: Error) => addToast('error', err.message || 'Failed to delete'),
  });

  const applyMutation = useMutation({
    mutationFn: ({ id, day }: { id: number; day: string }) => applyTemplate(id, day),
    onMutate: ({ id }) => setPendingId(id),
    onSettled: () => setPendingId(null),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['day-entries'] });
      addToast('success', `Added ${res.count} entr${res.count === 1 ? 'y' : 'ies'}`);
    },
    onError: (err: Error) => addToast('error', err.message || 'Failed to apply'),
  });

  if (authLoading || isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  const templates = data?.templates ?? [];
  const targetDay = selectedDate || '';

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Meal templates</h1>
        <Button onClick={() => setCreatingNew(true)}>New template</Button>
      </div>

      {templates.length === 0 ? (
        <div className="rounded-xl border-2 border-dashed border-border bg-card/40 p-8 text-center">
          <p className="text-sm text-muted-foreground">
            No templates yet. Save recurring meals and combinations to log them with one tap.
          </p>
          <div className="mt-4">
            <Button onClick={() => setCreatingNew(true)}>Create your first template</Button>
          </div>
        </div>
      ) : (
        <ul className="flex flex-col gap-2">
          {templates.map((t) => (
            <li
              key={t.id}
              className="rounded-xl border-2 border-border bg-card overflow-hidden"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                <div className="flex items-center gap-2 min-w-0">
                  <button
                    type="button"
                    onClick={() => favoriteMutation.mutate(t)}
                    className="size-8 shrink-0 flex items-center justify-center rounded-md hover:bg-white/5 transition-colors cursor-pointer"
                    title={t.is_favorite ? 'Unstar' : 'Star as favorite'}
                    aria-label={t.is_favorite ? 'Remove from favorites' : 'Add to favorites'}
                  >
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill={t.is_favorite ? '#f59e0b' : 'none'}
                      stroke={t.is_favorite ? '#f59e0b' : 'currentColor'}
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                    </svg>
                  </button>
                  <div className="flex flex-col min-w-0">
                    <span className="text-sm font-medium text-foreground truncate">{t.name}</span>
                    <span className="text-xs text-muted-foreground">
                      {t.items.length} item{t.items.length === 1 ? '' : 's'}
                      {' · '}
                      {t.items.reduce((sum, it) => sum + (it.amount || 0), 0)} kcal
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    onClick={() => applyMutation.mutate({ id: t.id, day: targetDay })}
                    disabled={pendingId === t.id || !targetDay}
                    title={targetDay ? `Apply to ${targetDay}` : 'Open dashboard to pick a day'}
                  >
                    {pendingId === t.id ? 'Applying…' : 'Apply'}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => {
                      if (window.confirm(`Delete "${t.name}"?`)) {
                        deleteMutation.mutate(t.id);
                      }
                    }}
                  >
                    Delete
                  </Button>
                </div>
              </div>
              {t.items.length > 0 && (
                <ul className="border-t border-border px-4 py-2 flex flex-col gap-1">
                  {t.items.map((it) => (
                    <li
                      key={it.id}
                      className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground"
                    >
                      <span className="text-foreground">{it.entry_name || '—'}</span>
                      <span>{it.amount} kcal</span>
                      {it.protein_g != null && <span>P {it.protein_g}g</span>}
                      {it.carbs_g != null && <span>C {it.carbs_g}g</span>}
                      {it.fat_g != null && <span>F {it.fat_g}g</span>}
                      {it.fiber_g != null && <span>Fi {it.fiber_g}g</span>}
                      {it.sugar_g != null && <span>S {it.sugar_g}g</span>}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}

      {(creatingNew || editing) && (
        <TemplateEditor
          isOpen
          template={editing}
          onClose={() => {
            setEditing(null);
            setCreatingNew(false);
          }}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['templates'] });
            setEditing(null);
            setCreatingNew(false);
          }}
        />
      )}
    </div>
  );
}
