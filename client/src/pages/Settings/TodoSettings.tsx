import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getTodos, createTodo, updateTodo, deleteTodo, toggleTodosEnabled } from '@/api/todos';
import type { User, Todo } from '@/types';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';
const timeInputClass = 'w-24 rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

const DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

interface ScheduleEditorProps {
  schedule: Todo['schedule'];
  onChange: (s: Todo['schedule']) => void;
}

function ScheduleEditor({ schedule, onChange }: ScheduleEditorProps) {
  const isDaily = schedule.type === 'daily';
  const days = schedule.type === 'weekdays' ? schedule.days : [];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
          <input
            type="radio"
            checked={isDaily}
            onChange={() => onChange({ type: 'daily' })}
            className="accent-primary"
          />
          Daily
        </label>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
          <input
            type="radio"
            checked={!isDaily}
            onChange={() => onChange({ type: 'weekdays', days: days.length > 0 ? days : [1, 2, 3, 4, 5] })}
            className="accent-primary"
          />
          Specific days
        </label>
      </div>
      {!isDaily && (
        <div className="flex gap-1 flex-wrap">
          {DAY_LABELS.map((label, i) => {
            const day = i + 1;
            const active = days.includes(day);
            return (
              <button
                key={day}
                type="button"
                onClick={() => {
                  const next = active ? days.filter((d) => d !== day) : [...days, day].sort();
                  if (next.length > 0) onChange({ type: 'weekdays', days: next });
                }}
                className={`px-2 py-1 text-xs rounded-md border transition-colors ${
                  active
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-input bg-muted/50 text-muted-foreground hover:border-ring'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface Props {
  user: User;
  onSave: () => void;
}

export default function TodoSettings({ user, onSave }: Props) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [enabled, setEnabled] = useState(user.todosEnabled);
  const [toggling, setToggling] = useState(false);

  const { data } = useQuery({
    queryKey: ['todos'],
    queryFn: getTodos,
    enabled,
  });

  const [newName, setNewName] = useState('');
  const [newSchedule, setNewSchedule] = useState<Todo['schedule']>({ type: 'daily' });
  const [newTime, setNewTime] = useState('');
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editName, setEditName] = useState('');
  const [editSchedule, setEditSchedule] = useState<Todo['schedule']>({ type: 'daily' });
  const [editTime, setEditTime] = useState('');
  const [saving, setSaving] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['todos'] });

  const handleToggleEnabled = async () => {
    setToggling(true);
    try {
      const newEnabled = !enabled;
      await toggleTodosEnabled(newEnabled);
      setEnabled(newEnabled);
      onSave();
    } catch {
      addToast('error', 'Failed to update setting');
    }
    setToggling(false);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    setCreating(true);
    try {
      await createTodo({ name: newName.trim(), schedule: newSchedule, time_of_day: newTime || null });
      setNewName('');
      setNewSchedule({ type: 'daily' });
      setNewTime('');
      setShowAddForm(false);
      refresh();
      addToast('success', 'Todo created');
    } catch {
      addToast('error', 'Failed to create todo');
    }
    setCreating(false);
  };

  const startEdit = (todo: Todo) => {
    setEditingId(todo.id);
    setEditName(todo.name);
    setEditSchedule(todo.schedule);
    setEditTime(todo.time_of_day || '');
  };

  const handleUpdate = async (id: number) => {
    if (!editName.trim()) return;
    setSaving(true);
    try {
      await updateTodo(id, { name: editName.trim(), schedule: editSchedule, time_of_day: editTime || null });
      setEditingId(null);
      refresh();
      addToast('success', 'Todo updated');
    } catch {
      addToast('error', 'Failed to update todo');
    }
    setSaving(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteTodo(id);
      refresh();
      addToast('success', 'Todo removed');
    } catch {
      addToast('error', 'Failed to remove todo');
    }
  };

  const formatSchedule = (schedule: Todo['schedule']) => {
    if (schedule.type === 'daily') return 'Daily';
    return schedule.days.map((d) => DAY_LABELS[d - 1]).join(', ');
  };

  const todos = data?.todos || [];

  return (
    <Card>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold">Todos</h3>
        <button
          type="button"
          onClick={handleToggleEnabled}
          disabled={toggling}
          className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
            enabled ? 'bg-primary' : 'bg-muted'
          } ${toggling ? 'opacity-50' : ''}`}
        >
          <span className={`pointer-events-none inline-block size-4 rounded-full bg-white shadow-sm transition-transform ${
            enabled ? 'translate-x-4' : 'translate-x-0'
          }`} />
        </button>
      </div>

      {enabled && (
        <div className="flex flex-col gap-3">
          {todos.length > 0 && (
            <ul className="divide-y divide-border rounded-md border border-border overflow-hidden">
              {todos.map((todo) => (
                <li key={todo.id}>
                  {editingId === todo.id ? (
                    <div className="flex flex-col gap-2 p-3 bg-muted/20">
                      <input
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        className={inputClass}
                        maxLength={100}
                        autoFocus
                      />
                      <div className="flex items-center gap-2">
                        <label className="text-xs text-muted-foreground shrink-0">Time</label>
                        <input
                          type="time"
                          value={editTime}
                          onChange={(e) => setEditTime(e.target.value)}
                          className={timeInputClass}
                        />
                        {editTime && (
                          <button type="button" onClick={() => setEditTime('')} className="text-xs text-muted-foreground hover:text-foreground">Clear</button>
                        )}
                      </div>
                      <ScheduleEditor schedule={editSchedule} onChange={setEditSchedule} />
                      <div className="flex gap-2">
                        <Button size="sm" onClick={() => handleUpdate(todo.id)} loading={saving}>Save</Button>
                        <Button size="sm" variant="ghost" onClick={() => setEditingId(null)}>Cancel</Button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-3 px-3 py-2.5 hover:bg-muted/10 transition-colors">
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-foreground truncate">{todo.name}</div>
                        <div className="text-xs text-muted-foreground">
                          {todo.time_of_day && <span>{todo.time_of_day} &middot; </span>}
                          {formatSchedule(todo.schedule)}
                        </div>
                      </div>
                      <div className="flex gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => startEdit(todo)}
                          className="text-xs text-muted-foreground hover:text-primary transition-colors"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(todo.id)}
                          className="text-xs text-muted-foreground hover:text-destructive transition-colors"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {showAddForm ? (
            <form onSubmit={handleCreate} className="flex flex-col gap-2 rounded-md border border-border p-3">
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Todo name"
                className={inputClass}
                maxLength={100}
                autoFocus
              />
              <div className="flex items-center gap-2">
                <label className="text-xs text-muted-foreground shrink-0">Time</label>
                <input
                  type="time"
                  value={newTime}
                  onChange={(e) => setNewTime(e.target.value)}
                  className={timeInputClass}
                />
                {newTime && (
                  <button type="button" onClick={() => setNewTime('')} className="text-xs text-muted-foreground hover:text-foreground">Clear</button>
                )}
              </div>
              <ScheduleEditor schedule={newSchedule} onChange={setNewSchedule} />
              <div className="flex gap-2">
                <Button type="submit" size="sm" loading={creating} disabled={!newName.trim()}>Add</Button>
                <Button type="button" size="sm" variant="ghost" onClick={() => { setShowAddForm(false); setNewName(''); setNewTime(''); setNewSchedule({ type: 'daily' }); }}>Cancel</Button>
              </div>
            </form>
          ) : (
            <button
              type="button"
              onClick={() => setShowAddForm(true)}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-primary transition-colors"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 5v14" /><path d="M5 12h14" />
              </svg>
              Add todo
            </button>
          )}
        </div>
      )}
    </Card>
  );
}
