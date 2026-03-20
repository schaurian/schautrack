export interface User {
  id: number;
  email: string;
  timezone: string;
  weightUnit: 'kg' | 'lb';
  dailyGoal: number | null;
  totpEnabled: boolean;
  macrosEnabled: Record<string, boolean>;
  macroGoals: Record<string, number>;
  goalThreshold: number;
  preferredAiProvider: string | null;
  hasAiKey: boolean;
  aiKeyLast4?: string;
  aiModel: string | null;
  aiDailyLimit: number | null;
  todosEnabled: boolean;
  notesEnabled: boolean;
  hasGlobalAiKey?: boolean;
}

export interface Entry {
  id: number;
  date: string;
  time: string;
  amount: number;
  name: string | null;
  macros: Record<string, number | null> | null;
}

export interface WeightEntry {
  id: number;
  entry_date: string;
  weight: number;
  timeFormatted?: string;
  updated_at?: string;
  created_at?: string;
}

export interface DailyStat {
  date: string;
  total: number;
  status: 'none' | 'zero' | 'under' | 'over' | 'over_threshold';
  overThreshold: boolean;
}

export interface SharedView {
  linkId?: number;
  userId: number;
  email: string;
  label: string;
  isSelf: boolean;
  dailyGoal: number | null;
  goalThreshold: number | null;
  dailyStats: DailyStat[];
  todayStr: string;
}

export interface MacroStatus {
  statusClass: string;
  statusText: string;
}

export interface AIUsage {
  used: number;
  limit: number;
  remaining: number;
}

export interface Todo {
  id: number;
  name: string;
  schedule: { type: 'daily' } | { type: 'weekdays'; days: number[] };
  time_of_day: string | null;
  sort_order: number;
  created_at?: string;
}

export interface TodoDay {
  id: number;
  name: string;
  time_of_day: string | null;
  completed: boolean;
  streak: number;
}

export interface DashboardData {
  user: User;
  dailyGoal: number | null;
  todayTotal: number;
  goalStatus: string;
  goalDelta: number | null;
  dailyStats: DailyStat[];
  dayOptions: string[];
  selectedDate: string;
  recentEntries: Entry[];
  sharedViews: SharedView[];
  weightUnit: string;
  timeZone: string;
  todayStr: string;
  range: { start: string; end: string; days: number; preset: number | null };
  weightEntry: WeightEntry | null;
  lastWeightEntry: WeightEntry | null;
  hasAiEnabled: boolean;
  aiUsage: AIUsage | null;
  aiProviderName: string | null;
  barcodeEnabled: boolean;
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  enabledMacros: string[];
  macroGoals: Record<string, number>;
  todayMacroTotals: Record<string, number>;
  macroLabels: Record<string, { short: string; label: string }>;
  macroModes: Record<string, string>;
  macroStatuses: Record<string, MacroStatus>;
  calorieStatus: MacroStatus;
}

export interface LinkRequest {
  id: number;
  email: string;
  created_at: string;
}

export interface AcceptedLink {
  linkId: number;
  userId: number;
  email: string;
  label: string | null;
  timezone: string;
  macros_enabled: Record<string, boolean>;
  macro_goals: Record<string, number>;
  goal_threshold: number | null;
}

export interface SettingsData {
  user: User;
  hasTempSecret: boolean;
  incomingRequests: LinkRequest[];
  outgoingRequests: LinkRequest[];
  acceptedLinks: AcceptedLink[];
  maxLinks: number;
  availableSlots: number;
  timezones: string[];
  linkFeedback: { type: string; message: string } | null;
  passwordFeedback: { type: string; message: string } | null;
  aiFeedback: { type: string; message: string } | null;
  emailFeedback: { type: string; message: string } | null;
  importFeedback: { type: string; message: string } | null;
}

export interface AdminData {
  users: Array<{
    id: number;
    email: string;
    email_verified: boolean;
    created_at: string;
  }>;
  settings: Record<string, { value: string; source: string }>;
}

export interface InviteCode {
  id: number;
  code: string;
  email: string | null;
  used_by: number | null;
  used_by_email: string | null;
  expires_at: string | null;
  created_at: string;
}
