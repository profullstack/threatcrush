export function parsePaginationParam(
  value: string | null,
  defaultValue: number,
  options: { min?: number; max?: number } = {},
) {
  if (value === null || value.trim() === "") {
    return defaultValue;
  }

  const parsed = Number(value);
  const min = options.min ?? 0;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;

  if (!Number.isInteger(parsed)) {
    return defaultValue;
  }

  return Math.min(Math.max(parsed, min), max);
}
