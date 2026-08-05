/**
 * Illustrations for the welcome tour.
 *
 * Each scene is a miniature of the real interface it describes — the same day
 * dots, the same activity ring, the same macro colors — rather than a generic
 * icon. Someone who reads the tour should recognise the shapes when they land
 * on the dashboard.
 *
 * Deliberately text-free: art that carries no words never needs translating,
 * and never breaks when a locale's string is twice as long.
 */

const KCAL = '#6d8cff';
const PROTEIN = '#22d3ee';
const CARBS = '#a78bfa';
const FAT = '#fb923c';
const FIBER = '#4ade80';
const SUCCESS = '#16a34a';
const WARNING = '#eab308';

const HAIRLINE = 'rgba(255,255,255,0.10)';
const FILL_FAINT = 'rgba(255,255,255,0.05)';

/** Shared frame: fixed aspect box so every step's art occupies identical space. */
function Scene({ children }: { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 320 132" className="h-full w-full" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}

/** A single day dot, matching DayDot's 22px rounded square. */
function Dot({ x, y, fill, size = 30, ring }: { x: number; y: number; fill: string; size?: number; ring?: string }) {
  return (
    <>
      <rect x={x} y={y} width={size} height={size} rx={9} fill={fill} />
      {ring && (
        <rect x={x - 3} y={y - 3} width={size + 6} height={size + 6} rx={12} fill="none" stroke={ring} strokeWidth={2} />
      )}
    </>
  );
}

/** Step 1 — the streak: a week of logged days, today still open. */
export function StreakArt() {
  const days = [FILL_FAINT, SUCCESS, SUCCESS, WARNING, SUCCESS, SUCCESS];
  return (
    <Scene>
      {/* Older days fade out, so the row reads as time running toward today
          instead of as six equal blocks. */}
      {days.map((fill, i) => (
        <g key={i} opacity={0.45 + i * 0.11}>
          <Dot x={16 + i * 43} y={53} fill={fill} size={26} />
        </g>
      ))}
      {/* Today: empty, ringed — the one waiting to be filled. */}
      <Dot x={16 + 6 * 43} y={53} fill={FILL_FAINT} size={26} ring={KCAL} />
    </Scene>
  );
}

/**
 * Step 2 — the ways to log. The photo chip is dropped when no AI key is
 * configured, matching the copy (and the dashboard, where the button is
 * genuinely absent).
 */
export function LogArt({ withAi = true }: { withAi?: boolean }) {
  // Two chips share the row when the photo route is unavailable.
  const chipW = withAi ? 92 : 142;
  const gap = withAi ? 9 : 10;
  const x = (i: number) => 13 + i * (chipW + gap);
  const mid = (i: number) => x(i) + chipW / 2;

  return (
    <Scene>
      {/* The entry field. */}
      <rect x={13} y={14} width={294} height={36} rx={10} fill={FILL_FAINT} stroke={HAIRLINE} />
      <rect x={27} y={27} width={2} height={12} rx={1} fill={KCAL} />
      <rect x={37} y={29} width={64} height={8} rx={4} fill="rgba(255,255,255,0.18)" />

      <g>
        <rect x={x(0)} y={66} width={chipW} height={48} rx={10} fill={FILL_FAINT} stroke={HAIRLINE} />
        {/* Pencil */}
        <g transform={`translate(${mid(0) - 59} 0)`}>
          <path d="M47 84 L58 84 L64 78 L58 72 L47 83 Z" fill="none" stroke={KCAL} strokeWidth={2} strokeLinejoin="round" />
          <path d="M46 96 L72 96" stroke={KCAL} strokeWidth={2} strokeLinecap="round" opacity={0.45} />
        </g>
      </g>
      <g>
        <rect x={x(1)} y={66} width={chipW} height={48} rx={10} fill={FILL_FAINT} stroke={HAIRLINE} />
        {/* Barcode */}
        <g transform={`translate(${mid(1) - 160} 0)`}>
          {[0, 6, 14, 19, 27, 33].map((dx, i) => (
            <rect key={i} x={143 + dx} y={78} width={i % 2 ? 2 : 3} height={24} rx={1} fill={PROTEIN} />
          ))}
        </g>
      </g>
      {withAi && (
        <g>
          <rect x={x(2)} y={66} width={chipW} height={48} rx={10} fill={FILL_FAINT} stroke={HAIRLINE} />
          {/* Camera */}
          <g transform={`translate(${mid(2) - 261} 0)`}>
            <rect x={243} y={80} width={36} height={24} rx={6} fill="none" stroke={CARBS} strokeWidth={2} />
            <path d="M254 80 L257 75 L265 75 L268 80" fill="none" stroke={CARBS} strokeWidth={2} strokeLinejoin="round" />
            <circle cx={261} cy={92} r={6} fill="none" stroke={CARBS} strokeWidth={2} />
          </g>
        </g>
      )}
    </Scene>
  );
}

/** Step 3 — the day dial: the calorie ring plus macro bars. */
export function DayArt() {
  const r = 34;
  const c = 2 * Math.PI * r;
  const bars: [string, number][] = [
    [PROTEIN, 0.68],
    [CARBS, 0.82],
    [FAT, 0.44],
    [FIBER, 0.3],
  ];
  return (
    <Scene>
      <g transform="rotate(-90 72 66)">
        <circle cx={72} cy={66} r={r} fill="none" stroke="rgba(255,255,255,0.09)" strokeWidth={7} />
        <circle
          cx={72}
          cy={66}
          r={r}
          fill="none"
          stroke={KCAL}
          strokeWidth={7}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * 0.28}
          style={{ filter: `drop-shadow(0 0 5px ${KCAL})` }}
        />
      </g>
      <rect x={57} y={61} width={30} height={9} rx={4.5} fill="rgba(255,255,255,0.35)" />

      {bars.map(([color, pct], i) => {
        const y = 25 + i * 24;
        return (
          <g key={color}>
            <circle cx={148} cy={y + 4} r={4} fill={color} />
            <rect x={162} y={y} width={145} height={9} rx={4.5} fill="rgba(255,255,255,0.07)" />
            <rect x={162} y={y} width={145 * pct} height={9} rx={4.5} fill={color} />
          </g>
        );
      })}
    </Scene>
  );
}

/** Step 4 — the plan: weight trending toward, but not yet at, a target. */
export function PlanArt() {
  const points = '20,26 66,36 112,34 158,48 204,56 250,68 296,74';
  const TARGET_Y = 104;
  return (
    <Scene>
      <defs>
        <linearGradient id="tour-plan-fade" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={FIBER} stopOpacity={0.2} />
          <stop offset="100%" stopColor={FIBER} stopOpacity={0} />
        </linearGradient>
      </defs>

      {/* The curve stops short of the dashed target: the plan is in progress,
          not finished. */}
      <polygon points={`${points} 296,${TARGET_Y} 20,${TARGET_Y}`} fill="url(#tour-plan-fade)" />
      <polyline points={points} fill="none" stroke={FIBER} strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" />
      {points.split(' ').map((p) => {
        const [x, y] = p.split(',');
        return <circle key={p} cx={x} cy={y} r={3.5} fill="#0e142a" stroke={FIBER} strokeWidth={2} />;
      })}

      <line x1={20} y1={TARGET_Y} x2={278} y2={TARGET_Y} stroke={CARBS} strokeWidth={1.5} strokeDasharray="5 5" opacity={0.6} />
      {/* Target marker, clear of the last reading. */}
      <rect x={286} y={TARGET_Y - 7} width={21} height={14} rx={5} fill={CARBS} opacity={0.9} />
    </Scene>
  );
}

/** Step 5 — linked accounts: someone else's week beside your own. */
export function ShareArt() {
  const mine = [SUCCESS, SUCCESS, WARNING, SUCCESS, SUCCESS];
  const theirs = [SUCCESS, WARNING, SUCCESS, SUCCESS, FILL_FAINT];
  return (
    <Scene>
      {/* The link: one bracket tying the two weeks together. */}
      <path
        d="M40 32 H30 a8 8 0 0 0 -8 8 V92 a8 8 0 0 0 8 8 H40"
        fill="none"
        stroke={CARBS}
        strokeWidth={2}
        strokeLinecap="round"
      />
      <circle cx={22} cy={66} r={5} fill={CARBS} />

      {mine.map((fill, i) => (
        <Dot key={`m${i}`} x={62 + i * 52} y={18} fill={fill} size={28} />
      ))}
      {/* Dimmed: a linked account's log is visible but read-only. */}
      <g opacity={0.6}>
        {theirs.map((fill, i) => (
          <Dot key={`t${i}`} x={62 + i * 52} y={86} fill={fill} size={28} />
        ))}
      </g>
    </Scene>
  );
}
