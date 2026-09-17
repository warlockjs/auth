/**
 * Spec-only narrowing for indexed reads (`rows[0]`, `mock.calls[0]`): returns
 * the value when present and fails the spec loudly when it is not, instead
 * of asserting it away with `!`.
 */
export function defined<T>(value: T | undefined, what = "value"): T {
  if (value === undefined) {
    throw new Error(`Expected ${what} to be defined.`);
  }

  return value;
}
