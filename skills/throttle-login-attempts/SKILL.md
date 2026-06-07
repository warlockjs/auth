---
name: throttle-login-attempts
description: 'Brute-force / credential-stuffing protection via `loginThrottleMiddleware` — a failure-aware route gate that counts only failed logins (resets on success), locks per-account and per-source after a threshold, and rejects pre-controller with 429 so the DB lookup and bcrypt verify are skipped. Cache-backed (shared across replicas), fixed-window, fails open on a cache outage. Triggers: `loginThrottleMiddleware`, `AuthErrorCodes.TooManyAttempts`, `EC004`, "rate limit login", "brute force protection", "lock account after failed logins", "throttle login attempts", "too many login attempts 429"; typical import `import { loginThrottleMiddleware } from "@warlock.js/auth"`. Skip: generic per-route request rate limiting that counts every request (use core `middleware.rateLimit`); gating a route by auth — `@warlock.js/auth/protect-routes/SKILL.md`; issuing tokens — `@warlock.js/auth/handle-login-and-logout/SKILL.md`.'
---

# Throttle login attempts with `loginThrottleMiddleware`

`loginThrottleMiddleware(options?)` returns a Warlock middleware that defends the login (and refresh / password-reset) routes against brute-force and credential-stuffing — without punishing a user who fat-fingers a password then gets it right.

The trick that makes it different from a plain rate limiter: it's **failure-aware**. It hooks the response *after* your controller runs (`response.onSent`), counts only the attempts that actually failed, and **clears the counter the moment a login succeeds**. A generic request limiter can't do that — it runs before the controller and counts every hit, success or not.

## The shortest version

```ts
import { loginThrottleMiddleware } from "@warlock.js/auth";

router.post("/auth/login", loginController, {
  middleware: [loginThrottleMiddleware()], // 5 failures / 15m → 15m lockout, per email + ip
});
```

That's the whole feature for most apps. Defaults: **5** failed attempts within a **15m** window trips a **15m** lockout, tracked independently per account (the `email` field) **and** per source IP.

## How it behaves

1. **Before the controller** — if the account or the IP is currently locked, it short-circuits with `429` and never touches the database or the bcrypt verify (this is also what neutralises the CPU-DoS angle of brute-forcing). The body carries `AuthErrorCodes.TooManyAttempts` (`EC004`).
2. **After the controller** — it inspects the outcome. A non-2xx response is a failed login: it bumps a fixed-window counter for each tracked identifier, and once a counter reaches `max` it writes a lock key. A 2xx response is a success: it **clears** the counter and lock for that identifier.

Per-account tracking stops a password-spray against one user from many IPs; per-source tracking stops one IP from stuffing many accounts. A lock on **either** identifier rejects the request — defense-in-depth.

## Options

```ts
loginThrottleMiddleware({
  max: 5,                 // failures allowed in the window before lockout
  window: "15m",          // counting window — ms-format string or seconds (number)
  lockoutDuration: "15m", // how long the lock lasts once tripped
  by: ["email", "ip"],    // identifiers tracked, each independently
  identifierKey: "email", // which credential field is the account key
  errorMessage: "Too many attempts. Try again later.",
});
```

Two escape hatches for non-standard setups:

```ts
loginThrottleMiddleware({
  // your controller signals failure with a 200 body instead of a status code
  isFailure: (response) => response.parsedBody?.ok === false,

  // derive the account key from somewhere other than email/ip
  identify: (request) => [`tenant.${request.input("tenant")}.${request.input("username")}`],
});
```

| Option | Default | Purpose |
| --- | --- | --- |
| `max` | `5` | Failures within the window before lockout |
| `window` | `"15m"` | Counting window (`ms`-string or seconds) |
| `lockoutDuration` | `"15m"` | Lock TTL once tripped |
| `by` | `["email", "ip"]` | Identifiers tracked independently |
| `identifierKey` | `"email"` | Credential field used as the account key |
| `errorMessage` | i18n `auth.errors.tooManyAttempts` | 429 message override |
| `isFailure` | `(res) => !res.isOk` | What counts as a failed attempt |
| `identify` | built-in email + ip extraction | Custom identifier list |

## The 429 response

On lockout the middleware sends:

```jsonc
{ "error": "...", "errorCode": "EC004" } // AuthErrorCodes.TooManyAttempts
```

Define the `auth.errors.tooManyAttempts` translation key (or pass `errorMessage`) so clients see a real message instead of the raw key. Map `EC004` in your error transformer the same way you map the other `AuthErrorCodes`.

## Beyond login

The middleware isn't login-specific — drop it on any route where repeated failures should lock something out. For the refresh and reset endpoints there's no email in the body, so track by IP only:

```ts
router.post("/auth/refresh-token", refreshController, {
  middleware: [loginThrottleMiddleware({ by: ["ip"], max: 10, window: "1m" })],
});

router.post("/auth/forgot-password", forgotController, {
  middleware: [loginThrottleMiddleware({ max: 3, window: "1h", lockoutDuration: "1h" })],
});
```

## When to use this vs core's `rateLimit`

| | `loginThrottleMiddleware` (auth) | `middleware.rateLimit` (core) |
| --- | --- | --- |
| Counts | only **failed** logins | **every** request |
| Resets on a successful login | yes | no |
| Locks per account / per IP | yes | per key (default IP) |
| Storage | `@warlock.js/cache` (shared across replicas) | in-process map |

They compose. For a hard ceiling on request volume *and* failure-aware account lockout, stack both: `middleware: [middleware.rateLimit({ max: 30, duration: 60_000 }), loginThrottleMiddleware()]`.

## Gotchas

- **Needs an initialised cache driver.** Storage is `@warlock.js/cache` (a peer dep, transitively present via core). If the driver isn't configured at runtime, the middleware **fails open** — it logs and lets the request through, because a throttle outage must never become an auth outage. That also means: no cache, no protection. Verify your cache config in production.
- **Account lockout can be weaponised.** An attacker who knows a victim's email can lock them out by spamming failures. The per-IP counter mitigates this (the attacker's IP locks too), but for purely anonymous endpoints prefer `by: ["ip"]`. For high-value accounts, consider a CAPTCHA step instead of a hard lock.
- **Fixed window, not sliding.** The window is anchored at the first failure and does not extend on each subsequent one — predictable lockout timing. The lock key is independent and always lasts `lockoutDuration`.
- **Defense-in-depth, not a WAF.** This is application-layer. It won't stop a volumetric L3/L4 flood — pair it with an edge/CDN rate limit for that.
- **Don't call it per-request.** Like every middleware, call it once at route definition; it returns the function that runs per request.

## See also

- [`@warlock.js/auth/protect-routes/SKILL.md`](@warlock.js/auth/protect-routes/SKILL.md) — gate a route behind a valid token (`authMiddleware`); stack the throttle in front of it on login routes.
- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — the login flow whose failures this middleware counts.
- [`@warlock.js/core/use-middleware/SKILL.md`](@warlock.js/core/use-middleware/SKILL.md) — `middleware.rateLimit` and the built-in middleware suite.
