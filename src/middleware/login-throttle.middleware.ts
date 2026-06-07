import { cache } from "@warlock.js/cache";
import { t, type Middleware, type Request, type Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * Built-in identifier kinds the throttle knows how to extract from a request.
 *
 * - `"email"` tracks per-account, so an attacker can't spray one user from
 *   many IPs.
 * - `"ip"` tracks per-source, so an attacker can't stuff many accounts from
 *   one IP.
 *
 * Lockout trips when ANY tracked identifier crosses `max` — defense-in-depth.
 */
export type LoginThrottleIdentifier = "email" | "ip";

/**
 * Options for {@link loginThrottleMiddleware}.
 *
 * Failure-aware by design: only counts requests whose response is non-2xx
 * (or whatever `isFailure` says) and resets on success, so a user who types
 * a wrong password three times then the right one is not penalised.
 *
 * @example
 * loginThrottleMiddleware({ max: 5, window: "15m", lockoutDuration: "15m" });
 */
export type LoginThrottleOptions = {
  /**
   * Failures allowed within the window before the identifier is locked.
   *
   * @default 5
   */
  max?: number;

  /**
   * Counting window. `ms`-format string (`"15m"`, `"1h"`) or seconds as a number.
   *
   * @default "15m"
   */
  window?: string | number;

  /**
   * Lockout duration once the threshold is tripped. `ms`-format string or seconds.
   *
   * @default "15m"
   */
  lockoutDuration?: string | number;

  /**
   * Identifiers tracked. Each is counted and locked independently.
   *
   * @default ["email", "ip"]
   */
  by?: LoginThrottleIdentifier[];

  /**
   * Credential field consulted when `"email"` is tracked. Switch to
   * `"username"` (or any other input field) for systems that don't
   * authenticate by email.
   *
   * @default "email"
   */
  identifierKey?: string;

  /**
   * Override the default error message returned with the 429 response.
   */
  errorMessage?: string;

  /**
   * Decide whether the response represents a failed login. Defaults to
   * "non-2xx is a failure"; override if your controller signals failure
   * through a 200-style body.
   *
   * @default (response) => !response.isOk
   */
  isFailure?: (response: Response) => boolean;

  /**
   * Compute the identifiers tracked for this request. Override to derive the
   * account key from a header, a JWT subject, or any other shape that does
   * not match the built-in `email` / `ip` extraction.
   */
  identify?: (request: Request) => string[];
};

const COUNTER_PREFIX = "auth.throttle.count.";
const LOCK_PREFIX = "auth.throttle.lock.";

const counterKey = (identifier: string): string => `${COUNTER_PREFIX}${identifier}`;
const lockKey = (identifier: string): string => `${LOCK_PREFIX}${identifier}`;

/**
 * Built-in identifier extractor — reads the configured credential field from
 * the request body for the per-account key, and `request.detectIp()` for the
 * per-source key. Untruthy values are dropped; a request that yields zero
 * identifiers is left untracked so the middleware no-ops for it.
 */
function buildDefaultIdentifiers(
  request: Request,
  tracked: LoginThrottleIdentifier[],
  credentialField: string,
): string[] {
  const identifiers: string[] = [];

  if (tracked.includes("email")) {
    const value = request.input(credentialField);

    if (typeof value === "string" && value.length > 0) {
      identifiers.push(`email.${value.toLowerCase()}`);
    }
  }

  if (tracked.includes("ip")) {
    const ip = request.detectIp();

    if (ip) {
      identifiers.push(`ip.${ip}`);
    }
  }

  return identifiers;
}

/**
 * Failure-aware login throttle. Locks an identifier (account, IP, or both)
 * after too many failed login attempts within a window — without penalising
 * a user who eventually types the right password.
 *
 * Mechanism (per identifier):
 *
 * 1. **Before the controller** — reject with `429` if a lock key is set,
 *    skipping the DB lookup AND the bcrypt verify (this also neutralises the
 *    CPU-DoS angle of brute-forcing).
 * 2. **After the controller** — observe the outcome via `response.onSent`.
 *    On failure (non-2xx by default), bump a fixed-window counter; once it
 *    reaches `max`, set a lock key with `lockoutDuration` TTL. On success,
 *    clear both the counter and the lock for that identifier.
 *
 * Storage is `@warlock.js/cache` (a peer dependency of `@warlock.js/auth`,
 * transitively guaranteed via `@warlock.js/core`). Lockout state is shared
 * across replicas — correct security model, because an attacker can't bypass
 * by round-robin to a different pod. Every cache call is guarded so a
 * misconfigured driver fails open (a throttle outage must never escalate
 * into a full auth outage).
 *
 * @example
 * import { loginThrottleMiddleware } from "@warlock.js/auth";
 * import { router } from "@warlock.js/core";
 *
 * router.post("/auth/login", loginController, {
 *   middleware: [loginThrottleMiddleware({ max: 5, window: "15m" })],
 * });
 *
 * @example
 * // Per-IP only — avoid account-lockout-as-DoS on anonymous-attack vectors
 * router.post("/auth/refresh-token", refreshController, {
 *   middleware: [loginThrottleMiddleware({ by: ["ip"], max: 10, window: "1m" })],
 * });
 */
export function loginThrottleMiddleware(options: LoginThrottleOptions = {}): Middleware {
  const max = options.max ?? 5;
  const window = options.window ?? "15m";
  const lockoutDuration = options.lockoutDuration ?? "15m";
  const tracked = options.by ?? ["email", "ip"];
  const credentialField = options.identifierKey ?? "email";

  return async (request: Request, response: Response) => {
    const identifiers = options.identify
      ? options.identify(request)
      : buildDefaultIdentifiers(request, tracked, credentialField);

    if (identifiers.length === 0) return;

    try {
      for (const identifier of identifiers) {
        const locked = await cache.get(lockKey(identifier));

        if (locked) {
          return response.tooManyRequests({
            error: options.errorMessage ?? t("auth.errors.tooManyAttempts"),
            errorCode: AuthErrorCodes.TooManyAttempts,
          });
        }
      }
    } catch (error) {
      // Fail open — a cache outage (driver not initialised, network blip)
      // must never escalate into a full auth outage. Log and let the request
      // through; the onSent recorder below is independently guarded so an
      // outage there is also harmless.
      log.error("auth", "login-throttle", error);

      return;
    }

    response.onSent(async (resolvedResponse: Response) => {
      try {
        const failed = options.isFailure
          ? options.isFailure(resolvedResponse)
          : !resolvedResponse.isOk;

        if (!failed) {
          for (const identifier of identifiers) {
            await cache.remove(counterKey(identifier));
            await cache.remove(lockKey(identifier));
          }

          return;
        }

        for (const identifier of identifiers) {
          const existing = await cache.get(counterKey(identifier));
          const ttlOption = existing === null ? { ttl: window } : undefined;
          const count = await cache.update<number>(
            counterKey(identifier),
            (current) => (current ?? 0) + 1,
            ttlOption,
          );

          if ((count ?? 0) >= max) {
            await cache.set(lockKey(identifier), true, { ttl: lockoutDuration });
          }
        }
      } catch (error) {
        log.error("auth", "login-throttle", error);
      }
    });
  };
}
