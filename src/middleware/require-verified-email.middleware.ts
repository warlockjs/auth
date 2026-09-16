import type { Middleware } from "@warlock.js/core";
import { EmailNotVerifiedError } from "../errors/email-not-verified.error";
import { authConfig } from "../services/auth-config";

/**
 * Opt-in route gate that rejects a user who has not verified their email with
 * {@link EmailNotVerifiedError} (`403`, `EC007`). Place it AFTER
 * `authMiddleware` — it reads `request.locals.user`. A request with no user
 * fails closed with the same error.
 *
 * @example
 * router.post("/orders", createOrder, {
 *   middleware: [authMiddleware("user"), requireVerifiedEmail()],
 * });
 */
export function requireVerifiedEmail(): Middleware {
  return async ({ request }) => {
    const user = request.locals.user as { get?: (key: string) => unknown } | undefined;

    if (!user?.get?.(authConfig.verification.field())) {
      throw new EmailNotVerifiedError();
    }
  };
}
