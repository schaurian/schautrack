import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { listSavedFoodsWithShared, trackSavedFood } from '@/api/savedFoods';
import { deleteEntry } from '@/api/entries';
import { useToastStore } from '@/stores/toastStore';
import { Button } from '@/components/ui/Button';
import { QuantityStepper } from '@/components/ui/QuantityStepper';
import { cn } from '@/lib/utils';
import type { SavedFood } from '@/types';
import SavedFoodsModal from './SavedFoodsModal';

interface Props {
  selectedDate: string;
  /**
   * Called after a chip successfully tracks an entry. The add sheet uses it to
   * close itself, the same way submitting the form does — tracking a quick-add
   * is finishing the task, so leaving the sheet up is a dead end.
   */
  onTracked?: () => void;
}

const DESKTOP_CHIPS = 8;
const MOBILE_CHIPS = 6;
const LONG_PRESS_MS = 450;

export default function SavedFoodsRow({ selectedDate, onTracked }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [modalOpen, setModalOpen] = useState(false);
  const [tracking, setTracking] = useState<number | null>(null);
  const [quantityPickerId, setQuantityPickerId] = useState<number | null>(null);
  // "+ more" unfolds the rest of the chips in place. It used to open the Manage
  // dialog, which stopped being able to track anything once the per-row Track
  // button was dropped — so every food past the cut became unloggable (#489).
  // Manage is still one tap away in the header; it is for editing the list.
  const [expanded, setExpanded] = useState(false);

  // scope=all, under a key nested beneath ['savedFoods'] so the existing
  // invalidateQueries({ queryKey: ['savedFoods'] }) calls still reach it by
  // prefix — and so the Manage dialog and the Settings counter, which share the
  // bare key, keep receiving own-foods-only.
  const { data } = useQuery({
    queryKey: ['savedFoods', 'all'],
    queryFn: listSavedFoodsWithShared,
  });

  const all = data?.savedFoods ?? [];
  // Split rather than interleave. Borrowed chips sort after the caller's own so
  // a friend adding a food never reshuffles positions the caller has muscle
  // memory for, and they get their own group so they stay reachable: ranked
  // into one list they would fall past the 6/8-chip cut for anyone with a
  // handful of foods, which hides the whole feature behind "+ more".
  const mine = all.filter((f) => !f.owner);
  const borrowed = all.filter((f) => f.owner);
  if (all.length === 0) return null;

  const handleTrack = async (food: SavedFood, quantity: number) => {
    if (tracking) return;
    setTracking(food.id);
    try {
      const res = await trackSavedFood(food.id, selectedDate, quantity);
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['day-entries'] });
      queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
      const entryId = res.entry.id;
      const label = t('savedFoods.toastTracked', { count: quantity, name: food.name });
      addToast('success', label, {
        label: t('savedFoods.undoLabel'),
        onClick: async () => {
          try {
            await deleteEntry(entryId);
            queryClient.invalidateQueries({ queryKey: ['dashboard'] });
            queryClient.invalidateQueries({ queryKey: ['day-entries'] });
            queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : t('savedFoods.toastUndoFailed'));
          }
        },
      });
      onTracked?.();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('savedFoods.toastTrackFailed'));
    }
    setTracking(null);
  };

  const renderChip = (food: SavedFood) => (
    <Chip
      key={food.id}
      food={food}
      loading={tracking === food.id}
      quantityPickerOpen={quantityPickerId === food.id}
      onTrack={(qty) => handleTrack(food, qty)}
      onOpenQuantity={() => setQuantityPickerId(food.id)}
      onCloseQuantity={() => setQuantityPickerId(null)}
    />
  );

  return (
    <>
      <div data-testid="saved-foods-row" className="rounded-2xl border border-white/[0.06] bg-white/[0.015] overflow-hidden">
        <div className="px-4 py-2 border-b border-white/[0.06] flex items-center justify-between">
          <h3 className="text-sm font-medium text-muted-foreground">{t('savedFoods.sectionTitle')}</h3>
          <Button size="sm" variant="outline" onClick={() => setModalOpen(true)}>
            {t('savedFoods.manageButton')}
          </Button>
        </div>
        <div className="flex flex-wrap gap-1.5 p-3">
          {expanded ? (
            // One list once everything is shown: the two breakpoint lists below
            // only exist to cut at a different count per width, and rendering
            // both here would duplicate every chip in the DOM.
            mine.map(renderChip)
          ) : (
            <>
              <div className="contents max-sm:hidden">
                {mine.slice(0, DESKTOP_CHIPS).map(renderChip)}
              </div>
              <div className="contents sm:hidden">
                {mine.slice(0, MOBILE_CHIPS).map(renderChip)}
              </div>
            </>
          )}
          {mine.length > MOBILE_CHIPS && (
            <button
              type="button"
              className={cn(
                'rounded-full border border-dashed border-border bg-transparent text-muted-foreground px-3 py-1 text-sm hover:text-foreground hover:border-ring cursor-pointer transition-colors',
                // Nothing is folded away on desktop until the desktop cut is
                // passed, so don't offer to unfold there.
                !expanded && mine.length <= DESKTOP_CHIPS && 'sm:hidden',
              )}
              aria-expanded={expanded}
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? t('savedFoods.lessButton') : t('savedFoods.moreButton')}
            </button>
          )}
        </div>

        {borrowed.length > 0 && (
          <div className="border-t border-white/[0.06] px-3 pb-3 pt-2" data-testid="saved-foods-shared">
            <p className="mb-1.5 text-xs text-muted-foreground">{t('savedFoods.sharedHeading')}</p>
            <div className="flex flex-wrap gap-1.5">
              {(expanded ? borrowed : borrowed.slice(0, MOBILE_CHIPS)).map(renderChip)}
            </div>
          </div>
        )}
      </div>

      <SavedFoodsModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
      />
    </>
  );
}

interface ChipProps {
  food: SavedFood;
  loading: boolean;
  quantityPickerOpen: boolean;
  onTrack: (quantity: number) => void;
  onOpenQuantity: () => void;
  onCloseQuantity: () => void;
}

function Chip({ food, loading, quantityPickerOpen, onTrack, onOpenQuantity, onCloseQuantity }: ChipProps) {
  const { t } = useTranslation('dashboard');
  const longPressTimerRef = useRef<number | null>(null);
  const longPressFiredRef = useRef(false);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const [pickerQty, setPickerQty] = useState(2);

  const parts: string[] = [];
  if (food.amount != null) parts.push(`${food.amount} kcal`);
  for (const [key, val] of Object.entries(food.macros)) {
    if (val != null) parts.push(`${val}g ${key}`);
  }
  // Whose food this is goes in the tooltip AND the accessible name, not just a
  // visual marker. A borrowed chip logs whatever its owner currently has it
  // set to — nothing is copied — so if they change "Coffee" from 5 to 500 kcal
  // the next tap logs 500. Being able to see whose item it is before tapping is
  // what makes that acceptable.
  const ownerSuffix = food.owner ? t('savedFoods.chipTooltipOwner', { owner: food.owner }) : '';
  const tooltip = `${t('savedFoods.chipTooltipBase', { name: food.name })}${parts.length > 0 ? t('savedFoods.chipTooltipDetails', { details: parts.join(' · ') }) : ''}${ownerSuffix}${t('savedFoods.chipTooltipHint')}`;

  // Reset the picker quantity each time it opens so consecutive uses
  // don't carry over the previous selection.
  useEffect(() => {
    if (quantityPickerOpen) setPickerQty(2);
  }, [quantityPickerOpen]);

  // Click-outside dismiss for the popover.
  useEffect(() => {
    if (!quantityPickerOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      if (!popoverRef.current) return;
      if (popoverRef.current.contains(e.target as Node)) return;
      onCloseQuantity();
    };
    // Defer one tick so the opening pointer-up doesn't immediately close us.
    const id = window.setTimeout(() => {
      document.addEventListener('pointerdown', onPointerDown);
    }, 0);
    return () => {
      window.clearTimeout(id);
      document.removeEventListener('pointerdown', onPointerDown);
    };
  }, [quantityPickerOpen, onCloseQuantity]);

  // Move focus into the popover when it opens so keyboard users land inside it.
  useEffect(() => {
    if (!quantityPickerOpen) return;
    const first = popoverRef.current?.querySelector<HTMLElement>('button, [tabindex]');
    first?.focus();
  }, [quantityPickerOpen]);

  const clearLongPressTimer = () => {
    if (longPressTimerRef.current != null) {
      window.clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
  };

  const handlePointerDown = (e: React.PointerEvent) => {
    if (quantityPickerOpen) return;
    longPressFiredRef.current = false;
    // Pointer capture would prevent the popover children from receiving events.
    (e.target as Element).releasePointerCapture?.(e.pointerId);
    longPressTimerRef.current = window.setTimeout(() => {
      longPressFiredRef.current = true;
      onOpenQuantity();
    }, LONG_PRESS_MS);
  };

  const handlePointerUp = () => {
    clearLongPressTimer();
  };

  const handleClick = () => {
    if (longPressFiredRef.current) {
      longPressFiredRef.current = false;
      return;
    }
    onTrack(1);
  };

  const closeAndRestoreFocus = () => {
    onCloseQuantity();
    triggerRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (quantityPickerOpen) return;
    // Shift+Enter / Shift+Space is the keyboard equivalent of long-press:
    // open the quantity picker instead of logging a single unit.
    if (e.shiftKey && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      onOpenQuantity();
    }
  };

  const handleContextMenu = (e: React.MouseEvent) => {
    // Right-click is the desktop equivalent of long-press; open the picker.
    e.preventDefault();
    if (!quantityPickerOpen) onOpenQuantity();
  };

  return (
    <div className="relative inline-block">
      <button
        ref={triggerRef}
        type="button"
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        onPointerDown={handlePointerDown}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        onPointerCancel={handlePointerUp}
        onContextMenu={handleContextMenu}
        disabled={loading}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full border border-border bg-white/[0.02] px-3 py-1 text-sm',
          'hover:bg-primary/10 hover:border-primary/40 hover:text-primary transition-colors cursor-pointer',
          'disabled:opacity-50 disabled:cursor-not-allowed',
          'touch-none', // prevent iOS text-selection callout on long-press
        )}
        title={tooltip}
        aria-label={food.owner ? t('savedFoods.chipSharedAriaLabel', { name: food.name, owner: food.owner }) : undefined}
      >
        {food.emoji && <span className="text-base leading-none">{food.emoji}</span>}
        <span className="font-medium">{food.name}</span>
        {food.owner && (
          <span className="text-xs text-muted-foreground/80">{food.owner}</span>
        )}
      </button>

      {quantityPickerOpen && (
        <div
          ref={popoverRef}
          role="dialog"
          aria-label={t('savedFoods.chooseQuantityAriaLabel', { name: food.name })}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation();
              closeAndRestoreFocus();
            }
          }}
          className="absolute left-1/2 z-20 mb-2 -translate-x-1/2 bottom-full flex flex-col items-center gap-2 rounded-lg border-2 border-border bg-card p-3 shadow-lg"
        >
          <QuantityStepper value={pickerQty} onChange={setPickerQty} />
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={closeAndRestoreFocus}
            >
              {t('savedFoods.cancelButton')}
            </Button>
            <Button
              size="sm"
              onClick={() => {
                onCloseQuantity();
                onTrack(pickerQty);
              }}
              loading={loading}
            >
              {t('savedFoods.logQuantityButton', { count: pickerQty })}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
