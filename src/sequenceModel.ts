/**
 * The sequence check's parameters (the statistics panel's "sequences" kind,
 * backend sequence.py): the fields naming a stream, the field numbering its
 * messages, the counter's wrap and the drop that counts as a restart. Pure:
 * the host checks what the panel or a command sent, and keeps the last ones.
 */

/** The wraps a sequence counter may have (none, 8, 16, 24 or 32 bits). */
export const SEQUENCE_WRAPS = [0, 2 ** 8, 2 ** 16, 2 ** 24, 2 ** 32] as const;
/** The backend's default restart window (sequence.DEFAULT_REORDER). */
export const DEFAULT_REORDER = 1000;
/** Key fields at most (statistics.MAX_SEQUENCE_KEYS). */
export const MAX_SEQUENCE_KEYS = 4;

export interface SequenceParams {
  key: string[];
  seq: string;
  wrap: number;
  reorder: number;
}

const FIELD_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/** A field name as typed, or "" when it can't be one. */
const fieldName = (v: unknown): string =>
  typeof v === "string" && FIELD_RE.test(v.trim()) ? v.trim() : "";

/**
 * The parameters in `raw` that make sense (field names, a known wrap, a
 * positive window), else the defaults: no key, no sequence field.
 */
export function normalizeSequenceParams(raw: unknown): SequenceParams {
  const o = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const keys = Array.isArray(o.key) ? o.key : typeof o.key === "string" ? o.key.split(",") : [];
  const key = [...new Set(keys.map(fieldName).filter((k) => k))].slice(0, MAX_SEQUENCE_KEYS);
  const wrap = SEQUENCE_WRAPS.find((w) => w === o.wrap) ?? 0;
  const reorder =
    typeof o.reorder === "number" && Number.isInteger(o.reorder) && o.reorder >= 1
      ? Math.min(o.reorder, 2 ** 31)
      : DEFAULT_REORDER;
  return { key, seq: fieldName(o.seq), wrap, reorder };
}
