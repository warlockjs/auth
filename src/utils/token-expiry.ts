import { createDecoder } from "fast-jwt";

/**
 * Payload decoder. Deliberately signature-*unaware*: these helpers answer
 * "does this token carry a deadline at all", which is a property of the claims,
 * not of the signature. Every caller that acts on the answer (the middleware,
 * the purge command) has already verified the signature or is about to delete
 * the row anyway.
 */
const decodePayload = createDecoder();

/**
 * Whether a persisted `expires_at` can serve as a deadline at all.
 *
 * Answers `false` for absent, empty, and — the case that matters — `Invalid
 * Date`, which is what a pre-4.12.0 unparseable `expiresIn` wrote to the token
 * row. An `Invalid Date` compares `false` against *every* other date, so a row
 * holding one satisfies neither `expires_at < now` (cleanup never purges it)
 * nor `expires_at > now` (it never shows as an active session): it is outside
 * the reach of every date predicate rather than merely wrong.
 */
export function isUsableExpiry(value: unknown): boolean {
  if (value === undefined || value === null || value === "") return false;

  return !Number.isNaN(new Date(value as string | number | Date).getTime());
}

/**
 * Whether the JWT carries a finite numeric `exp` claim.
 *
 * This is the store-independent signal for a never-expiring credential: a
 * token with no `exp` has nothing for a verifier to check, so it verifies
 * indefinitely no matter what the row beside it says. An undecodable string
 * answers `false` — it cannot be shown to expire, and a row whose token cannot
 * even be parsed is unusable regardless.
 */
export function tokenHasExpClaim(token: unknown): boolean {
  if (typeof token !== "string" || token === "") return false;

  try {
    const payload = decodePayload(token) as { exp?: unknown } | null;

    return typeof payload?.exp === "number" && Number.isFinite(payload.exp);
  } catch {
    return false;
  }
}

/**
 * Whether a token row can ever stop being accepted on its own.
 *
 * Two independent ways to answer "no", either of which is enough:
 * - the persisted expiry is unusable, so no date check can ever retire the row;
 * - the token itself carries no `exp`, so signature verification never retires it.
 *
 * This is the predicate the `auth.purge-never-expiring` remediation selects on.
 */
export function isNeverExpiring(token: unknown, expiresAt: unknown): boolean {
  return !isUsableExpiry(expiresAt) || !tokenHasExpClaim(token);
}
