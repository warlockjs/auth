import type { Middleware } from "@warlock.js/core";
import { loginThrottleMiddleware, type LoginThrottleOptions } from "./login-throttle.middleware";
import { tokenIssueThrottleMiddleware } from "./one-time-token-throttle.middleware";

/**
 * Throttle for the route that SENDS a login code. {@link tokenIssueThrottleMiddleware}
 * keyed on the `phone` input and IP: every request counts (the answer is the
 * same for unknown phones), 3 per 1h, then a 1h lockout (`429`, `EC004`).
 *
 * @example
 * router.post("/auth/otp/request", requestOtpController, {
 *   middleware: [otpRequestThrottleMiddleware()],
 * });
 */
export function otpRequestThrottleMiddleware(options: LoginThrottleOptions = {}): Middleware {
  return tokenIssueThrottleMiddleware({ identifierKey: "phone", ...options });
}

/**
 * Throttle for the route that VERIFIES a login code. {@link loginThrottleMiddleware}
 * keyed on `phone` and IP, failure-aware: 5 failures per 15m, then a 15m lockout
 * (`429`, `EC004`). Complements the per-code attempt cap, which a fresh code
 * would otherwise reset.
 *
 * @example
 * router.post("/auth/otp/verify", verifyOtpController, {
 *   middleware: [otpVerifyThrottleMiddleware()],
 * });
 */
export function otpVerifyThrottleMiddleware(options: LoginThrottleOptions = {}): Middleware {
  return loginThrottleMiddleware({
    max: 5,
    window: "15m",
    lockoutDuration: "15m",
    by: ["email", "ip"],
    identifierKey: "phone",
    ...options,
  });
}
