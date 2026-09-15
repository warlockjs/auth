import { useCurrentUser } from "@warlock.js/core";
import type { Auth } from "../models/auth.model";

/**
 * Typed accessor over the request-scoped current user, for callers that want
 * `Auth`-derived typing without repeating core's `unknown` → `UserType`
 * assertion at every call site.
 *
 * Core's own `useCurrentUser()` returns `unknown` cast to the caller's
 * generic (it cannot know about `RequestUser`/`Auth` — see
 * `core/src/http/context/request-context.ts`). This wrapper narrows that
 * generic to `Auth`, matching what `@warlock.js/auth`'s middleware actually
 * writes to `request.locals.user`.
 *
 * @example
 * const user = currentUser<AdminUser>();
 */
export function currentUser<UserType extends Auth = Auth>(): UserType | undefined {
  return useCurrentUser<UserType>();
}
