import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { listSavedFoods, trackSavedFood } from '@/api/savedFoods';
import { deleteEntry } from '@/api/entries';
import { useToastStore } from '@/stores/toastStore';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import type { SavedFood } from '@/types';
import SavedFoodsModal from './SavedFoodsModal';

interface Props {
  selectedDate: string;
}

const DESKTOP_CHIPS = 8;
const MOBILE_CHIPS = 6;

export default function SavedFoodsRow({ selectedDate }: Props) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [modalOpen, setModalOpen] = useState(false);
  const [tracking, setTracking] = useState<number | null>(null);

  const { data } = useQuery({
    queryKey: ['savedFoods'],
    queryFn: listSavedFoods,
  });

  const all = data?.savedFoods ?? [];
  if (all.length === 0) return null;

  const handleTrack = async (food: SavedFood) => {
    if (tracking) return;
    setTracking(food.id);
    try {
      const res = await trackSavedFood(food.id, selectedDate);
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['day-entries'] });
      queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
      const entryId = res.entry.id;
      addToast('success', `Tracked ${food.name}`, {
        label: 'Undo',
        onClick: async () => {
          try {
            await deleteEntry(entryId);
            queryClient.invalidateQueries({ queryKey: ['dashboard'] });
            queryClient.invalidateQueries({ queryKey: ['day-entries'] });
            queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : 'Undo failed');
          }
        },
      });
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to track');
    }
    setTracking(null);
  };

  return (
    <>
      <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
        <div className="px-4 py-2 border-b-2 border-border flex items-center justify-between">
          <h3 className="text-sm font-medium text-muted-foreground">Quick add</h3>
          <Button size="sm" variant="outline" onClick={() => setModalOpen(true)}>
            Manage
          </Button>
        </div>
        <div className="flex flex-wrap gap-1.5 p-3">
          <div className="contents max-sm:hidden">
            {all.slice(0, DESKTOP_CHIPS).map((food) => (
              <Chip key={food.id} food={food} loading={tracking === food.id} onTrack={() => handleTrack(food)} />
            ))}
          </div>
          <div className="contents sm:hidden">
            {all.slice(0, MOBILE_CHIPS).map((food) => (
              <Chip key={food.id} food={food} loading={tracking === food.id} onTrack={() => handleTrack(food)} />
            ))}
          </div>
          {(all.length > DESKTOP_CHIPS || (all.length > MOBILE_CHIPS)) && (
            <button
              type="button"
              className="rounded-full border border-dashed border-border bg-transparent text-muted-foreground px-3 py-1 text-sm hover:text-foreground hover:border-ring cursor-pointer transition-colors"
              onClick={() => setModalOpen(true)}
            >
              + more
            </button>
          )}
        </div>
      </div>

      <SavedFoodsModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        selectedDate={selectedDate}
      />
    </>
  );
}

function Chip({ food, loading, onTrack }: { food: SavedFood; loading: boolean; onTrack: () => void }) {
  const parts: string[] = [];
  if (food.amount != null) parts.push(`${food.amount} kcal`);
  for (const [key, val] of Object.entries(food.macros)) {
    if (val != null) parts.push(`${val}g ${key}`);
  }
  const tooltip = `Track ${food.name}${parts.length > 0 ? ` — ${parts.join(' · ')}` : ''}`;

  return (
    <button
      type="button"
      onClick={onTrack}
      disabled={loading}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border border-border bg-white/[0.02] px-3 py-1 text-sm',
        'hover:bg-primary/10 hover:border-primary/40 hover:text-primary transition-colors cursor-pointer',
        'disabled:opacity-50 disabled:cursor-not-allowed',
      )}
      title={tooltip}
    >
      {food.emoji && <span className="text-base leading-none">{food.emoji}</span>}
      <span className="font-medium">{food.name}</span>
    </button>
  );
}
