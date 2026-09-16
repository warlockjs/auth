import { timingSafeEqual } from "node:crypto";

/** Constant-time string equality; strings of unequal length are simply unequal. */
export function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);

  return a.length === b.length && timingSafeEqual(a, b);
}
