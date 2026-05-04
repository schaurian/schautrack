import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import TemplateEditor from '../Templates/TemplateEditor';
import type { Entry } from '@/types';

interface Props {
  entries: Entry[];
  selectedDate: string;
}

function entriesToPreset(entries: Entry[]) {
  return entries.map((e) => ({
    entry_name: e.name || '',
    amount: e.amount === 0 ? '' : String(e.amount),
    protein_g: e.macros?.protein != null ? String(e.macros.protein) : '',
    carbs_g: e.macros?.carbs != null ? String(e.macros.carbs) : '',
    fat_g: e.macros?.fat != null ? String(e.macros.fat) : '',
    fiber_g: e.macros?.fiber != null ? String(e.macros.fiber) : '',
    sugar_g: e.macros?.sugar != null ? String(e.macros.sugar) : '',
  }));
}

export default function SaveTodayAsTemplateButton({ entries, selectedDate }: Props) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();

  const disabled = entries.length === 0;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={disabled}
        title={disabled ? 'Track entries first, then save them as a template' : 'Save these entries as a reusable template'}
        className="text-xs text-muted-foreground hover:text-foreground disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
      >
        Save as template
      </button>
      {open && (
        <TemplateEditor
          isOpen
          template={null}
          presetItems={entriesToPreset(entries)}
          presetName={`Entries from ${selectedDate}`}
          onClose={() => setOpen(false)}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['templates'] });
            setOpen(false);
          }}
        />
      )}
    </>
  );
}
