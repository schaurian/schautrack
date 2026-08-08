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
  bodyFatEnabled: boolean;
  /** False until the welcome tour is dismissed — drives its first-run open. */
  onboardingCompleted: boolean;
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
  /** Percent. null on days measured by a scale that only reports weight. */
  body_fat: number | null;
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
  rate_per_week: number | null;
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

/** Bounds are weights, so they are in `PlanResponse.unit` — not necessarily kg. */
export interface HealthyRange {
  min: number;
  max: number;
}

export interface CurvePoint {
  week: number;
  weight: number;
}

export interface BodyComposition {
  date: string;
  bodyFatPct: number;
  /**
   * In the user's weight unit, like every other weight on PlanResponse. This is
   * the measured percentage applied to the weight the plan works from, i.e. the
   * same lean mass the BMR was computed at — not the weight the reading was
   * originally taken at.
   */
  leanMass: number;
  fatMass: number;
  category: 'essential' | 'athletic' | 'fitness' | 'average' | 'obese' | null;
  /** Whole days between the reading and today. Negative if dated ahead. */
  ageDays: number;
  /**
   * True when the reading is too old to pick the BMR formula (server-side
   * window). A stale reading is still shown — it is the user's latest
   * measurement — but `computed.bmrFormula` will be `mifflin_st_jeor`.
   */
  stale: boolean;
}

export interface PlanComputed {
  bmr: number;
  tdee: number;
  budgetKcal: number;
  budgetClamped: boolean;
  /** A weight per week, in `PlanResponse.unit`. */
  ratePerWeek: number;
  etaWeeks: number;
  etaDate: string | null;
  planCurve: CurvePoint[];
  bmrFormula: 'mifflin_st_jeor' | 'katch_mcardle';
}

export interface PlanTrend {
  /** A weight per week, in `PlanResponse.unit`. Negative when losing. */
  slopePerWeek: number;
  hasData: boolean;
  projectedWeeks: number;
  projectedDate: string | null;
  status: 'ahead' | 'on_track' | 'behind' | 'stalled' | 'wrong_direction' | 'insufficient_data';
}

export interface SeriesPoint {
  date: string;
  weight: number;
  bodyFat?: number;
}

export interface PlanWarning {
  code: string;
  message: string;
}

export interface PlanResponse {
  /**
   * The unit every weight-valued field below is in — the account's, not
   * necessarily kg. No field on this payload names a unit itself; this is the
   * one place that says which one they are in.
   */
  unit: 'kg' | 'lb';
  metrics: PlanMetrics;
  currentWeight: number | null;
  bmi: number | null;
  bmiCategory: string | null;
  composition: BodyComposition | null;
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
