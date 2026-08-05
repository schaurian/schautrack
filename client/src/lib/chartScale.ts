/**
 * Axis scaling helpers for the plan chart.
 *
 * Splitting a domain into N equal parts is mathematically correct but
 * unreadable: a 54.7-130 range divided in three labels the axis 54.7 / 79.8 /
 * 104.9 / 130. Readers anchor on round numbers, so ticks are snapped to a
 * 1 / 2 / 5 x 10^n increment and only those landing inside the domain are kept.
 */

/**
 * Trims binary-float drift (0.1 * 3 = 0.30000000000000004) without discarding
 * real precision. Uses significant digits rather than decimal places: rounding
 * to 6 decimals would collapse a legitimately tiny step to 0, and a zero step
 * makes the tick loop divide by zero.
 */
const clean = (n: number) => (Number.isFinite(n) ? Number(n.toPrecision(12)) : n);

// Geometric-mean thresholds pick the *nearest* allowed step rather than always
// rounding up, which would systematically emit fewer ticks than requested.
// Same heuristic d3-array uses for tickIncrement.
const E10 = Math.sqrt(50); // 7.07
const E5 = Math.sqrt(10); // 3.16
const E2 = Math.sqrt(2); // 1.41

/**
 * Chooses a round step covering [min, max] in roughly `targetCount` intervals.
 * Always returns a positive, finite number.
 */
export function niceStep(min: number, max: number, targetCount = 6): number {
  const span = Math.abs(max - min);
  if (!Number.isFinite(span) || span === 0) return 1;

  const raw = span / Math.max(targetCount - 1, 1);
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const normalized = raw / magnitude;

  const factor = normalized >= E10 ? 10 : normalized >= E5 ? 5 : normalized >= E2 ? 2 : 1;
  return clean(factor * magnitude);
}

/**
 * Round-numbered ticks lying inside [min, max].
 *
 * Ticks are placed *within* the domain rather than the domain being widened to
 * meet them: widening trades away vertical resolution, which is the whole
 * problem this chart had. Callers pad their domain a little so the extreme data
 * points do not sit flush against the frame.
 */
export function niceTicks(min: number, max: number, targetCount = 6): number[] {
  if (!Number.isFinite(min) || !Number.isFinite(max)) return [];

  const lo = Math.min(min, max);
  const hi = Math.max(min, max);
  if (lo === hi) return [clean(lo)];

  const step = niceStep(lo, hi, targetCount);
  if (!Number.isFinite(step) || step <= 0) return [];

  const first = Math.ceil(lo / step) * step;

  // Derive the count and multiply, rather than accumulating by +=, so the last
  // tick is exact. The epsilon keeps a tick that lands exactly on `hi`.
  const count = Math.floor((hi - first) / step + 1e-9);
  if (!Number.isFinite(count) || count < 0) return [];

  return Array.from({ length: count + 1 }, (_, i) => clean(first + i * step));
}

/**
 * Clamps a band (e.g. the healthy-weight range) to the plotted area.
 *
 * The band is context, not data: it must never widen the domain, or a healthy
 * range sitting 50kg below anything the user has logged would squash the actual
 * trend into a corner. Returns null when the band falls entirely outside the
 * plot, which callers use to drop it from the legend too.
 *
 * All values are screen-space y coordinates, where y grows downward.
 */
export function clampBand(
  top: number,
  bottom: number,
  plotTop: number,
  plotBottom: number,
): { top: number; bottom: number } | null {
  if (![top, bottom, plotTop, plotBottom].every(Number.isFinite)) return null;

  const hi = Math.min(top, bottom);
  const lo = Math.max(top, bottom);

  // Fully above or fully below the plot — nothing to draw.
  if (lo <= plotTop || hi >= plotBottom) return null;

  const clampedTop = Math.max(hi, plotTop);
  const clampedBottom = Math.min(lo, plotBottom);
  if (clampedBottom - clampedTop <= 0) return null;

  return { top: clampedTop, bottom: clampedBottom };
}
