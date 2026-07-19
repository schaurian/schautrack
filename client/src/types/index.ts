export interface User {
  id: number;
  email: string;
  timezone: string;
  weightUnit: 'kg' | 'lb';
  language: string | null;
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
  passkeyCount: number;
  oidcLinked: boolean;
  authMethod: 'password' | 'passkey' | 'oidc' | '';
  heightCm?: number | null;
  birthYear?: number | null;
  sex?: 'male' | 'female' | 'other' | null;
  activityLevel?: string | null;
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

export interface LinkShares {
  nutrition: boolean;
  weight: boolean;
  todos: boolean;
  notes: boolean;
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
  shares: LinkShares;
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
  missed_since?: string;
}

export interface SavedFood {
  id: number;
  name: string;
  emoji: string | null;
  amount: number | null;
  macros: {
    protein: number | null;
    carbs: number | null;
    fat: number | null;
    fiber: number | null;
    sugar: number | null;
  };
  use_count: number;
  last_used_at: string | null;
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
  shares: LinkShares;
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

// --- Weight-loss planner ---
// NOTE: WeightGoal uses SNAKE_CASE keys (it's a reused domain model, matching
// the Go model.WeightGoal JSON tags). Everything else on PlanResponse is
// camelCase, as emitted by the plan handler/assembler.

export interface WeightGoal {
  id: number;
  user_id: number;
  start_weight: number;
  start_date: string;
  target_weight: number;
  pace_mode: 'rate' | 'date';
  rate_kg_per_week: number | null;
  target_date: string | null;
  activity_level: string | null;
  status: 'active' | 'achieved' | 'abandoned';
  achieved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PlanMetrics {
  heightCm: number | null;
  birthYear: number | null;
  sex: string | null;
  activityLevel: string | null;
  complete: boolean;
}

export interface HealthyRange {
  minKg: number;
  maxKg: number;
}

export interface CurvePoint {
  week: number;
  weight: number;
}

export interface PlanComputed {
  bmr: number;
  tdee: number;
  budgetKcal: number;
  budgetClamped: boolean;
  rateKgPerWeek: number;
  etaWeeks: number;
  etaDate: string | null;
  planCurve: CurvePoint[];
}

export interface PlanTrend {
  slopeKgPerWeek: number;
  hasData: boolean;
  projectedWeeks: number;
  projectedDate: string | null;
  status: 'ahead' | 'on_track' | 'behind' | 'stalled' | 'wrong_direction' | 'insufficient_data';
}

export interface SeriesPoint {
  date: string;
  weight: number;
}

export interface PlanWarning {
  code: string;
  message: string;
}

export interface PlanResponse {
  metrics: PlanMetrics;
  currentWeight: number | null;
  bmi: number | null;
  bmiCategory: string | null;
  healthyRange: HealthyRange | null;
  goal: WeightGoal | null;
  computed: PlanComputed | null;
  trend: PlanTrend | null;
  currentCalorieGoal: number | null;
  series: SeriesPoint[];
  warnings: PlanWarning[];
  disclaimer: string;
}

// Request body for PUT /plan/metrics — snake_case, matches the Go handler's
// body struct exactly. Partial updates are fine (omitted fields preserved).
export interface BodyMetrics {
  height_cm?: number | null;
  birth_year?: number | null;
  sex?: 'male' | 'female' | 'other' | null;
  activity_level?: string | null;
}
