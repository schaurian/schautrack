import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listSavedFoods } from '@/api/savedFoods';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import SavedFoodsModal from '@/pages/Dashboard/SavedFoodsModal';

export default function SavedFoodsSettings() {
  const [open, setOpen] = useState(false);
  const { data } = useQuery({
    queryKey: ['savedFoods'],
    queryFn: listSavedFoods,
  });
  const count = data?.savedFoods.length ?? 0;

  return (
    <Card>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold">Saved foods</h3>
      </div>
      <p className="text-xs text-muted-foreground mb-3">
        Quick-add chips on the dashboard. {count} saved.
      </p>
      <Button variant="outline" className="w-full" onClick={() => setOpen(true)}>
        Manage saved foods
      </Button>
      <SavedFoodsModal isOpen={open} onClose={() => setOpen(false)} />
    </Card>
  );
}
