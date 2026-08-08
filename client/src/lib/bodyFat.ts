/**
 * Client-side parsing of the body-fat input, kept in lockstep with the server's
 * `service.ParseBodyFat` and the `weight_entries_body_fat_range` CHECK.
 *
 * It exists so an out-of-range percentage fails where the user typed it instead
 * of round-tripping to the server just to come back as a generic error toast.
 */

/** Mirror of `service.MaxBodyFatPct`. Deliberately loose — the highest values
 *  ever recorded are around 70 — and the bound is inclusive on both sides:
 *  0 < pct <= 75. */
export const MAX_BODY_FAT_PCT = 75;

/**
 * The three outcomes of reading the field, matching the three states the
 * `body_fat` key has on the wire: `null` clears the stored reading, a number
 * sets it, and an unusable value is rejected without a request.
 */
export type BodyFatInput =
  | { ok: true; value: number | null }
  | { ok: false };

export function parseBodyFatInput(raw: string): BodyFatInput {
  const trimmed = raw.trim();
  if (trimmed === '') return { ok: true, value: null };
  // Same comma-decimal tolerance as the server, and the same length guard so a
  // pasted essay never reaches parseFloat.
  if (trimmed.length > 12) return { ok: false };
  const num = Number(trimmed.replace(',', '.'));
  if (!Number.isFinite(num) || num <= 0 || num > MAX_BODY_FAT_PCT) return { ok: false };
  return { ok: true, value: num };
}
