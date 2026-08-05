/**
 * Seeds the demo account the README screenshots are taken from.
 *
 *   npx tsx scripts/demo-seed.ts
 *
 * Every feature is switched on and filled with plausible history, because an
 * empty dashboard shows nothing worth screenshotting: macros with a part-filled
 * ring, six weeks of entries so the timeline has texture, a downward weight
 * trend for the planner, todos mid-streak, a note, quick-add chips and an
 * accepted friend link.
 *
 * Deterministic on purpose — same data every run, so regenerated screenshots
 * differ only when the UI actually changed.
 */
import { execFileSync } from 'child_process';

const DEMO_EMAIL = 'demo@schautrack.app';
const FRIEND_EMAIL = 'friend@schautrack.app';
// bcrypt of "demo1234demo" — a throwaway credential for a throwaway database.
const DEMO_HASH = '$2b$10$yGfth4QccMugcvNRMqNLhOPdL.1j9UI00W7Fy4oKBEWjriE8OdV6W';

const DB_CONTAINER = process.env.DB_CONTAINER || detectDbContainer();
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';

function detectDbContainer(): string {
  const out = execFileSync('sh', ['-c', 'docker ps --format "{{.Names}}" | grep -E "schautrack.*db"'], { encoding: 'utf-8' }).trim();
  const names = out.split('\n').map((n) => n.trim()).filter(Boolean);
  return names.find((n) => n.includes('test')) || names[0] || 'schautrack-test-db-1';
}

function psql(sql: string): string {
  const raw = execFileSync('docker', ['exec', '-i', DB_CONTAINER, 'psql', '-U', DB_USER, '-d', DB_NAME, '-tA'], {
    input: sql + '\n',
    encoding: 'utf-8',
  }).trim();
  // Drop command tags ("INSERT 0 1") so a RETURNING value comes back clean.
  return raw
    .split('\n')
    .filter((l) => !/^(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s/.test(l))
    .join('\n')
    .trim();
}

/** Local date N days back, formatted YYYY-MM-DD. */
function day(offset: number): string {
  const d = new Date();
  d.setUTCHours(12, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() - offset);
  return d.toISOString().slice(0, 10);
}

// onboarding_completed_at is set on both branches: a demo account that has
// never dismissed the welcome tour gets it opened over the dashboard, and the
// modal then intercepts every click the screenshot run tries to make. The
// conflict branch matters too — the seed re-runs against a persistent test DB.
function upsertUser(email: string): string {
  return psql(`
    INSERT INTO users (email, password_hash, email_verified, onboarding_completed_at)
    VALUES ('${email}', '${DEMO_HASH}', true, NOW())
    ON CONFLICT (email) DO UPDATE SET
      password_hash = EXCLUDED.password_hash,
      email_verified = true,
      onboarding_completed_at = COALESCE(users.onboarding_completed_at, NOW())
    RETURNING id`);
}

function wipe(userId: string) {
  psql(`DELETE FROM calorie_entries WHERE user_id = ${userId}`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${userId}`);
  psql(`DELETE FROM todo_completions WHERE user_id = ${userId}`);
  psql(`DELETE FROM todos WHERE user_id = ${userId}`);
  psql(`DELETE FROM daily_notes WHERE user_id = ${userId}`);
  psql(`DELETE FROM saved_foods WHERE user_id = ${userId}`);
  psql(`DELETE FROM weight_goals WHERE user_id = ${userId}`);
}

// Meals, and the day templates built from them. The templates matter: the day
// dot takes the *worst* macro status, and a macro in target mode that finishes
// more than the threshold below goal counts as danger — so a plausible-looking
// day that lands at 95g of a 150g protein target paints the whole timeline red.
// Each template below meets protein and fiber and stays under the limits.
const MEALS: Record<string, [string, number, number, number, number, number, number]> = {
  // name, kcal, protein, carbs, fat, fiber, sugar
  porridge:   ['Porridge with banana', 380, 14, 62, 8, 8, 18],
  yoghurt:    ['Greek yoghurt & berries', 240, 22, 22, 7, 5, 16],
  eggs:       ['Scrambled eggs on toast', 430, 26, 34, 21, 5, 4],
  salad:      ['Chicken salad bowl', 520, 46, 38, 19, 10, 8],
  lentils:    ['Lentil soup & bread', 460, 24, 63, 12, 15, 9],
  tuna:       ['Tuna sandwich', 490, 34, 48, 17, 7, 6],
  salmon:     ['Salmon, rice & broccoli', 640, 46, 61, 22, 10, 5],
  bolognese:  ['Pasta bolognese', 720, 40, 84, 24, 9, 12],
  tofu:       ['Stir-fried tofu & noodles', 610, 32, 72, 21, 11, 11],
  almonds:    ['Apple & almonds', 210, 7, 22, 12, 7, 15],
  shake:      ['Protein shake', 180, 28, 9, 3, 3, 5],
  chocolate:  ['Dark chocolate', 160, 2, 15, 11, 3, 12],
  skyr:       ['Skyr with honey', 200, 24, 18, 2, 2, 14],
  chickpeas:  ['Chickpea curry & rice', 580, 26, 82, 15, 14, 10],
};

/** Meals per day, at the hour they were logged. */
const DAY_TEMPLATES: Array<Array<[string, number]>> = [
  // ~2080 kcal · 152p · 34fib — a good day
  [['porridge', 8], ['salad', 13], ['shake', 16], ['salmon', 19]],
  // ~2090 kcal · 148p · 37fib
  [['yoghurt', 8], ['lentils', 12], ['shake', 15], ['salmon', 19]],
  // ~2070 kcal · 150p · 33fib
  [['eggs', 8], ['tuna', 13], ['skyr', 16], ['tofu', 19]],
  // ~2100 kcal · 146p · 36fib
  [['porridge', 8], ['chickpeas', 13], ['shake', 16], ['salad', 19]],
  // ~2140 kcal · 154p · 31fib
  [['skyr', 8], ['salad', 12], ['almonds', 16], ['bolognese', 19]],
  // over goal — every timeline needs a few, or the colours never vary
  [['eggs', 8], ['bolognese', 13], ['chocolate', 16], ['bolognese', 20], ['almonds', 22]],
];

function insertEntry(userId: string, date: string, hour: number, key: string) {
  const [name, kcal, p, c, f, fib, s] = MEALS[key];
  psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g, fiber_g, sugar_g, created_at)
        VALUES (${userId}, '${date}', ${kcal}, '${name.replace(/'/g, "''")}', ${p}, ${c}, ${f}, ${fib}, ${s}, '${date} ${String(hour).padStart(2, '0')}:20:00+00')`);
}

function insertDay(userId: string, date: string, template: Array<[string, number]>) {
  for (const [key, hour] of template) insertEntry(userId, date, hour, key);
}

function seedDemo(userId: string) {
  wipe(userId);

  psql(`UPDATE users SET
      daily_goal = 2200,
      timezone = 'Europe/Berlin',
      timezone_manual = true,
      language = 'en',
      weight_unit = 'kg',
      todos_enabled = true,
      notes_enabled = true,
      height_cm = 182,
      birth_year = 1990,
      sex = 'male',
      activity_level = 'moderate',
      goal_threshold = 10,
      macros_enabled = '{"calories": true, "protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true, "auto_calc_calories": false}',
      macro_goals = '{"calories": 2200, "protein": 110, "carbs": 250, "fat": 70, "fiber": 25, "sugar": 55,
                      "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit",
                      "fat_mode": "limit", "fiber_mode": "target", "sugar_mode": "limit"}'
    WHERE id = ${userId}`);

  // Six weeks of history. Templates rotate so consecutive days differ, and the
  // over-goal template lands every seventh day so the timeline shows more than
  // one colour without looking like a losing streak.
  for (let back = 41; back >= 1; back--) {
    const template = back % 7 === 0 ? DAY_TEMPLATES[5] : DAY_TEMPLATES[back % 5];
    insertDay(userId, day(back), template);
  }

  // Today reads as a day nearly done: dinner logged, everything met or close.
  const today = day(0);
  insertDay(userId, today, DAY_TEMPLATES[0]);

  // 12 weeks of weight, trending down with real-looking noise.
  for (let back = 84; back >= 0; back -= 2) {
    const trend = 84.6 - (84 - back) * 0.055;
    const noise = Math.sin(back / 3) * 0.28;
    psql(`INSERT INTO weight_entries (user_id, entry_date, weight)
          VALUES (${userId}, '${day(back)}', ${(trend + noise).toFixed(1)})
          ON CONFLICT (user_id, entry_date) DO UPDATE SET weight = EXCLUDED.weight`);
  }

  psql(`INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode, rate_kg_per_week, activity_level, status)
        VALUES (${userId}, 84.6, '${day(84)}', 76.0, 'rate', 0.4, 'moderate', 'active')`);

  const todos: Array<[string, string, number]> = [
    ['Drink 2L of water', 'anytime', 0],
    ['Morning walk', 'morning', 1],
    ['Stretch 10 minutes', 'evening', 2],
    ['Take vitamin D', 'morning', 3],
  ];
  todos.forEach(([name, time, order], i) => {
    const id = psql(`INSERT INTO todos (user_id, name, schedule, time_of_day, sort_order)
                     VALUES (${userId}, '${name}', '{"type":"daily"}', '${time}', ${order}) RETURNING id`);
    // Streaks of different lengths, and two already ticked today so the list
    // shows both states.
    const streak = [12, 6, 3, 9][i];
    for (let back = i < 2 ? 0 : 1; back < streak; back++) {
      psql(`INSERT INTO todo_completions (todo_id, user_id, completion_date)
            VALUES (${id}, ${userId}, '${day(back)}') ON CONFLICT DO NOTHING`);
    }
  });

  psql(`INSERT INTO daily_notes (user_id, note_date, content)
        VALUES (${userId}, '${today}', 'Long walk after lunch. Hungry earlier than usual — moving dinner up a bit.')
        ON CONFLICT (user_id, note_date) DO UPDATE SET content = EXCLUDED.content`);

  const chips: Array<[string, string, number, number, number, number]> = [
    ['Porridge', '🥣', 380, 12, 62, 8],
    ['Protein shake', '🥤', 180, 27, 9, 3],
    ['Greek yoghurt', '🍶', 240, 20, 22, 7],
    ['Chicken salad', '🥗', 520, 42, 38, 19],
    ['Espresso', '☕', 5, 0, 1, 0],
    ['Banana', '🍌', 105, 1, 27, 0],
  ];
  for (const [name, emoji, kcal, p, c, f] of chips) {
    psql(`INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, carbs_g, fat_g)
          VALUES (${userId}, '${name}', '${emoji}', ${kcal}, ${p}, ${c}, ${f})`);
  }
}

function seedFriend(demoId: string, friendId: string) {
  wipe(friendId);
  psql(`UPDATE users SET daily_goal = 1900, timezone = 'Europe/Berlin', weight_unit = 'kg',
          macros_enabled = '{"calories": true, "protein": true}',
          macro_goals = '{"calories": 1900, "protein": 110, "calories_mode": "limit", "protein_mode": "target"}'
        WHERE id = ${friendId}`);

  for (let back = 20; back >= 0; back--) {
    insertDay(friendId, day(back), DAY_TEMPLATES[(back + 2) % 5]);
  }

  // Every link the demo account has, not just this pair: the database survives
  // between runs, so a link left by an earlier seed would show up as a second
  // friend row in the screenshots.
  psql(`DELETE FROM account_links WHERE requester_id = ${demoId} OR target_id = ${demoId}`);
  psql(`INSERT INTO account_links (requester_id, target_id, status, requester_label, target_label, requester_shares, target_shares)
        VALUES (${demoId}, ${friendId}, 'accepted', 'Friend', 'Demo',
                '{"nutrition": true, "weight": true, "todos": true, "notes": false}',
                '{"nutrition": true, "weight": false, "todos": true, "notes": false}')`);
}

const demoId = upsertUser(DEMO_EMAIL);
const friendId = upsertUser(FRIEND_EMAIL);
seedDemo(demoId);
seedFriend(demoId, friendId);

// Legal pages are an admin setting; the footer links look broken without them.
psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_legal', 'true')
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);

console.log(`demo account ready: ${DEMO_EMAIL} (id ${demoId}), friend ${FRIEND_EMAIL} (id ${friendId})`);
