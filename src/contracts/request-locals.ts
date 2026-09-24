/**
 * The authenticated user attached to the current request —
 * `request.locals.user`.
 *
 * Moved here from `@warlock.js/core` in 5.12.0 (core's `Request` no longer
 * has a `user` property at all — see `RequestUserMovedError`). Empty by
 * default, exactly as it was in core, so any shape is assignable at the
 * declaration site; an app narrows it via module augmentation:
 *
 * @example
 * ```typescript
 * declare module "@warlock.js/auth" {
 *   interface RequestUser {
 *     id: string | number;
 *   }
 * }
 * ```
 *
 * Deliberately NOT `extends Auth<ModelSchema>` here: an `interface` can
 * extend at most one class hierarchy, and a library-side
 * `interface RequestUser extends Auth<ModelSchema>` would pre-claim that one
 * extends slot, so an app's own `interface RequestUser extends User {}`
 * would fail to compile (TS2320). See `access/src/middleware/gate.middleware.ts`
 * for the same hazard documented at its call site.
 */
export interface RequestUser {}

/**
 * Augments core's `RequestLocals` (`request.locals`) with the `user` key —
 * done in the module that OWNS the key, per `RequestLocals`' own contract
 * (`core/src/http/types.ts`). `authMiddleware` (`middleware/auth.middleware.ts`)
 * is the sole writer: it sets `request.locals.user` after a successful token
 * resolution and clears it (`= undefined`) on a forged, malformed, expired,
 * or wrong-type token.
 */
declare module "@warlock.js/core" {
  interface RequestLocals {
    user?: RequestUser;
    /**
     * The in-flight or settled result of `resolveRequestUser`, memoised per
     * request so every caller shares one verify, one lookup and one renewal.
     */
    session?: Promise<any>;
  }
}
