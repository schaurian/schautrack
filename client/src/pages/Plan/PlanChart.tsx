import { useId, useMemo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { SeriesPoint, CurvePoint, HealthyRange } from '@/types';
import { cn } from '@/lib/utils';
import { formatDate } from '@/lib/format';

export interface PlanChartProps {
  series: SeriesPoint[];
  planCurve?: CurvePoint[];
  targetWeight?: number | null;
  healthyRange?: HealthyRange | null;
  weightUnit: string;
  /** 'full' = axes + legend for the /plan page. 'spark' = minimal, for a dashboard card. */
  variant?: 'full' | 'spark';
  className?: string;
}

const DAY_MS = 86_400_000;
const FULL_SIZE = { width: 640, height: 260 };
const SPARK_SIZE = { width: 240, height: 64 };

function startOfToday(): number {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * Cheap dependency-free curve smoothing: a quadratic-bezier through each
 * segment's midpoint. Gives a rounded polyline without full Catmull-Rom math.
 */
function smoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;
  let d = `M ${points[0].x} ${points[0].y}`;
  for (let i = 1; i < points.length - 1; i++) {
    const cur = points[i];
    const next = points[i + 1];
    const midX = (cur.x + next.x) / 2;
    const midY = (cur.y + next.y) / 2;
    d += ` Q ${cur.x} ${cur.y} ${midX} ${midY}`;
  }
  const last = points[points.length - 1];
  d += ` L ${last.x} ${last.y}`;
  return d;
}

function evenTicks(min: number, max: number, count: number): number[] {
  if (!Number.isFinite(min) || !Number.isFinite(max) || min === max) return [min];
  const step = (max - min) / (count - 1);
  return Array.from({ length: count }, (_, i) => min + step * i);
}

const fmtTickDate = (ts: number) => formatDate(ts, undefined, { month: 'short', day: 'numeric' });
const fmtWeight = (w: number) => (Number.isInteger(w) ? String(w) : w.toFixed(1));

function LegendItem({ swatch, label }: { swatch: ReactNode; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {swatch}
      <span>{label}</span>
    </span>
  );
}

export default function PlanChart({
  series,
  planCurve = [],
  targetWeight = null,
  healthyRange = null,
  weightUnit,
  variant = 'full',
  className,
}: PlanChartProps) {
  const { t } = useTranslation('dashboard');
  const titleId = useId();
  const isSpark = variant === 'spark';
  const size = isSpark ? SPARK_SIZE : FULL_SIZE;

  const layout = useMemo(() => {
    const actual = series
      .map((p) => ({ t: new Date(p.date).getTime(), w: p.weight }))
      .filter((p) => Number.isFinite(p.t) && Number.isFinite(p.w))
      .sort((a, b) => a.t - b.t);

    if (actual.length < 2) return null;

    // Plan-curve weeks are offsets from today — map onto the same timeline as the
    // logged series. Spark keeps the domain tight to logged history (no axes to
    // orient the reader to a projected range), so it skips the plan curve entirely.
    const today = startOfToday();
    const plan = isSpark ? [] : planCurve.map((p) => ({ t: today + p.week * 7 * DAY_MS, w: p.weight }));

    const tValues = [...actual.map((p) => p.t), ...plan.map((p) => p.t)];
    const wValues = [...actual.map((p) => p.w), ...plan.map((p) => p.w)];
    if (targetWeight != null) wValues.push(targetWeight);
    if (!isSpark && healthyRange) wValues.push(healthyRange.minKg, healthyRange.maxKg);

    const tMin = Math.min(...tValues);
    const tMax = Math.max(...tValues);
    let wMin = Math.min(...wValues);
    let wMax = Math.max(...wValues);
    if (wMin === wMax) {
      wMin -= 1;
      wMax += 1;
    }
    const pad = (wMax - wMin) * (isSpark ? 0.15 : 0.1);
    const wMinPadded = wMin - pad;
    const wMaxPadded = wMax + pad;

    const { width, height } = size;
    const margin = isSpark
      ? { top: 3, right: 3, bottom: 3, left: 3 }
      : { top: 10, right: 14, bottom: 26, left: 42 };
    const plotW = width - margin.left - margin.right;
    const plotH = height - margin.top - margin.bottom;

    const x = (t: number) => margin.left + (tMax === tMin ? plotW / 2 : ((t - tMin) / (tMax - tMin)) * plotW);
    const y = (w: number) =>
      margin.top + (1 - (w - wMinPadded) / (wMaxPadded - wMinPadded)) * plotH;

    return {
      margin,
      plotW,
      plotH,
      actualPts: actual.map((p) => ({ x: x(p.t), y: y(p.w) })),
      planPts: plan.map((p) => ({ x: x(p.t), y: y(p.w) })),
      targetY: targetWeight != null ? y(targetWeight) : null,
      bandY: !isSpark && healthyRange ? { top: y(healthyRange.maxKg), bottom: y(healthyRange.minKg) } : null,
      xAxisTicks: isSpark ? [] : [tMin, (tMin + tMax) / 2, tMax].map((t) => ({ t, x: x(t) })),
      yAxisTicks: isSpark ? [] : evenTicks(wMin, wMax, 4).map((w) => ({ w, y: y(w) })),
    };
  }, [series, planCurve, targetWeight, healthyRange, isSpark, size]);

  const chartTitle = isSpark
    ? `${t('plan.chart.sparkTitle')}${targetWeight != null ? t('plan.chart.sparkTitleTarget', { value: fmtWeight(targetWeight), unit: weightUnit }) : ''}`
    : `${t('plan.chart.fullTitleBase')}${planCurve.length ? t('plan.chart.fullTitlePlanCurveSuffix') : ''}${
        targetWeight != null ? t('plan.chart.fullTitleTargetSuffix', { value: fmtWeight(targetWeight), unit: weightUnit }) : ''
      }${t('plan.chart.fullTitleInUnitSuffix', { unit: weightUnit })}`;

  if (!layout) {
    const message = t('plan.chart.noDataMessage');
    if (isSpark) {
      return (
        <div
          className={cn('flex items-center justify-center text-center text-[10px] text-muted-foreground', className)}
          style={{ minHeight: size.height }}
        >
          {message}
        </div>
      );
    }
    return (
      <div className={cn('surface overflow-hidden', className)}>
        <div className="px-4 pt-4 pb-2">
          <h3 className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">{t('plan.chart.title')}</h3>
        </div>
        <div className="p-8 flex items-center justify-center min-h-[200px]">
          <span className="text-sm text-muted-foreground text-center">{message}</span>
        </div>
      </div>
    );
  }

  const { margin, plotW, plotH, actualPts, planPts, targetY, bandY, xAxisTicks, yAxisTicks } = layout;
  const actualPath = smoothPath(actualPts);
  const planPath = smoothPath(planPts);

  const svg = (
    <svg
      viewBox={`0 0 ${size.width} ${size.height}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-labelledby={titleId}
      style={{ width: '100%', height: 'auto', display: 'block', minWidth: isSpark ? 120 : 480 }}
    >
      <title id={titleId}>{chartTitle}</title>

      {/* Healthy-range band */}
      {bandY && (
        <rect
          x={margin.left}
          y={bandY.top}
          width={plotW}
          height={Math.max(bandY.bottom - bandY.top, 0)}
          className="fill-success/12"
        />
      )}

      {/* Gridlines (recessive, one step off the surface) */}
      {!isSpark &&
        yAxisTicks.map(({ w, y: ty }) => (
          <line key={`grid-${w}`} x1={margin.left} x2={margin.left + plotW} y1={ty} y2={ty} className="stroke-border" strokeWidth={1} />
        ))}

      {/* Target-weight reference line — neutral, dashed; not a data series */}
      {targetY != null && (
        <line
          x1={margin.left}
          x2={margin.left + plotW}
          y1={targetY}
          y2={targetY}
          className="text-muted-foreground"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeDasharray="4 3"
          strokeLinecap="round"
        />
      )}

      {/* Adaptive plan curve — distinct hue + dash pattern (secondary encoding) */}
      {planPts.length >= 2 && (
        <path
          d={planPath}
          className="text-macro-fat"
          stroke="currentColor"
          strokeWidth={2}
          strokeDasharray="6 4"
          fill="none"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}

      {/* Actual logged weight */}
      <path d={actualPath} className="text-primary" stroke="currentColor" strokeWidth={2} fill="none" strokeLinecap="round" strokeLinejoin="round" />

      {!isSpark &&
        actualPts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={3.5} className="fill-primary" stroke="var(--color-card)" strokeWidth={2} />
        ))}

      {/* Baseline */}
      {!isSpark && (
        <line x1={margin.left} x2={margin.left + plotW} y1={margin.top + plotH} y2={margin.top + plotH} className="stroke-border" strokeWidth={1} />
      )}

      {/* Axis labels */}
      {!isSpark &&
        yAxisTicks.map(({ w, y: ty }) => (
          <text key={`ytick-${w}`} x={margin.left - 6} y={ty} textAnchor="end" dominantBaseline="middle" className="text-muted-foreground" fill="currentColor" fontSize={10}>
            {fmtWeight(w)}
          </text>
        ))}

      {!isSpark &&
        xAxisTicks.map(({ t, x: tx }, i) => (
          <text
            key={`xtick-${t}-${i}`}
            x={tx}
            y={size.height - 6}
            textAnchor={i === 0 ? 'start' : i === xAxisTicks.length - 1 ? 'end' : 'middle'}
            className="text-muted-foreground"
            fill="currentColor"
            fontSize={10}
          >
            {fmtTickDate(t)}
          </text>
        ))}
    </svg>
  );

  if (isSpark) {
    return <div className={cn('overflow-x-auto', className)}>{svg}</div>;
  }

  return (
    <div className={cn('surface overflow-hidden', className)}>
      <div className="px-4 pt-4 pb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">{t('plan.chart.title')}</h3>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
          <LegendItem swatch={<span className="inline-block h-0.5 w-3 rounded-full bg-primary" />} label={t('plan.chart.legendActual')} />
          {planCurve.length > 0 && (
            <LegendItem swatch={<span className="inline-block h-0 w-3 border-t-2 border-dashed border-macro-fat" />} label={t('plan.chart.legendPlan')} />
          )}
          {targetWeight != null && (
            <LegendItem swatch={<span className="inline-block h-0 w-3 border-t-2 border-dashed border-muted-foreground/70" />} label={t('plan.chart.legendTarget')} />
          )}
          {healthyRange && <LegendItem swatch={<span className="inline-block h-2.5 w-3 rounded-sm bg-success/20" />} label={t('plan.chart.legendHealthyRange')} />}
        </div>
      </div>
      <div className="p-4 overflow-x-auto">{svg}</div>
    </div>
  );
}
