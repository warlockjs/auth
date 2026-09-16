import type { Middleware } from "@warlock.js/core";
import { loginThrottleMiddleware, type LoginThrottleOptions } from "./login-throttle.middleware";

/**
 * Throttle for routes that ISSUE a verification or reset token ("send
 * verification email", "forgot password"). Built on
 * {@link loginThrottleMiddleware}, tracked per email and per IP, with one
 * difference: EVERY request counts. A reset request answers the same success
 * for known and unknown emails, so a failure-aware counter would never trip.
 *
 * Defaults: 3 requests per 1h window, then a 1h lockout (`429`, `EC004`).
 *
 * @example
 * router.post("/auth/forgot-password", forgotPassword, {
 *   middleware: [tokenIssueThrottleMiddleware()],
 * });
 */
export function tokenIssueThrottleMiddleware(options: LoginThrottleOptions = {}): Middleware {
  return loginThrottleMiddleware({
    max: 3,
    window: "1h",
    lockoutDuration: "1h",
    by: ["email", "ip"],
    isFailure: () => true,
    ...options,
  });
}

/**
 * Throttle for routes that CONSUME a token ("verify email", "reset
 * password"). Built on {@link loginThrottleMiddleware}: per IP (the body
 * carries a token, not an account), failure-aware — a rejected token counts,
 * a successful use clears the counter.
 *
 * Defaults: 10 failures per 15m window, then a 15m lockout (`429`, `EC004`).
 *
 * @example
 * router.post("/auth/reset-password", resetPasswordController, {
 *   middleware: [tokenConsumeThrottleMiddleware()],
 * });
 */
export function tokenConsumeThrottleMiddleware(options: LoginThrottleOptions = {}): Middleware {
  return loginThrottleMiddleware({
    max: 10,
    window: "15m",
    lockoutDuration: "15m",
    by: ["ip"],
    ...options,
  });
}
