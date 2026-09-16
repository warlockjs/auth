---
name: verify-email-and-reset-password
description: 'Email verification and password reset with hashed, single-use, expiring, purpose-bound tokens delivered through `@warlock.js/notifications` — `sendEmailVerification(user)`, `verifyEmail(token)`, `requestPasswordReset(Model, email)`, `resetPassword(token, newPassword)`, the `requireVerifiedEmail()` guard, and the `tokenIssueThrottleMiddleware` / `tokenConsumeThrottleMiddleware` presets. Reset revokes every access token, refresh token and cookie session; a reset request answers the same for unknown emails. Triggers: `sendEmailVerification`, `verifyEmail`, `requestPasswordReset`, `resetPassword`, `requireVerifiedEmail`, `isEmailVerified`, `OneTimeToken`, `InvalidOneTimeTokenError`, `EmailNotVerifiedError`, `NotificationsUnavailableError`, `EC007`, `EC008`, `auth.verification`, `auth.passwordReset`; "verify email", "confirm email address", "forgot password", "reset password link", "block unverified users", "resend verification email"; typical import `import { requestPasswordReset, resetPassword } from "@warlock.js/auth"`. Skip: sign-up itself — `@warlock.js/auth/register-user/SKILL.md`; login throttling — `@warlock.js/auth/throttle-login-attempts/SKILL.md`; defining notifications — `@warlock.js/notifications/define-notification/SKILL.md`.'
---

# Verify email + reset password

Four service functions, one guard, two throttle presets. Auth ships no controllers — wire the routes yourself (examples below).

## Prerequisites

1. **`@warlock.js/notifications` installed and configured with a `mail` channel.** It is an optional peer; without it (or without `src/config/notifications.ts`) every send/request call throws `NotificationsUnavailableError` **before** a token is issued — never a silent skip.
2. **The `one_time_tokens` table.** It ships in `authMigrations` next to the access/refresh tables; run your migrations.
3. **A verified-date field on the user schema** (default `emailVerifiedAt`):

```ts
export const userSchema = v.object({
  // ...
  emailVerifiedAt: v.date().optional(),
});
```

If the schema strips it, `verifyEmail` throws naming the field instead of pretending it worked.

## Tokens

- 32 random bytes, base64url. Only the **SHA-256 hash** is stored; the raw token exists only in the notification.
- **Single use**, consumed with a conditional update — of two concurrent uses, exactly one succeeds.
- **Expiring**: verification `24h`, reset `60m` by default.
- **Purpose-bound**: a verification token is never accepted by `resetPassword`, and vice versa.
- A new reset request **invalidates the user's earlier unused reset tokens**. Verification tokens are not invalidated by a resend.
- Unknown, wrong-purpose, expired and used tokens all throw one `InvalidOneTimeTokenError` (`400`, `EC008`).

## Email verification

```ts
import { requireVerifiedEmail, sendEmailVerification, verifyEmail } from "@warlock.js/auth";
import { type RequestHandler } from "@warlock.js/core";

// after User.create(...) in your register controller
await sendEmailVerification(user);

export const verifyEmailController: RequestHandler = async ({ request, response }) => {
  const user = await verifyEmail(request.input("token")); // throws InvalidOneTimeTokenError
  return response.success({ user });
};

router.post("/auth/verify-email", verifyEmailController, {
  middleware: [tokenConsumeThrottleMiddleware()],
});

router.post("/auth/verify-email/resend", resendController, {
  middleware: [authMiddleware("user"), tokenIssueThrottleMiddleware({ by: ["ip"] })],
});

// Opt-in guard, AFTER authMiddleware: 403 EmailNotVerifiedError (EC007)
router.post("/orders", createOrder, {
  middleware: [authMiddleware("user"), requireVerifiedEmail()],
});
```

`isEmailVerified(user)` answers the same question in code.

## Password reset

```ts
import { requestPasswordReset, resetPassword } from "@warlock.js/auth";

export const forgotPasswordController: RequestHandler = async ({ request, response }) => {
  await requestPasswordReset(User, request.input("email"));
  // Same answer whether or not the account exists.
  return response.success({ message: "If that account exists, we sent a reset link." });
};

export const resetPasswordController: RequestHandler = async ({ request, response }) => {
  // Validate strength FIRST — the token is consumed before the password is written.
  await resetPassword(request.input("token"), request.input("password"));
  return response.success({ message: "Password updated. Please log in again." });
};

router.post("/auth/forgot-password", forgotPasswordController, {
  middleware: [tokenIssueThrottleMiddleware()], // 3 / 1h per email + per IP
});
router.post("/auth/reset-password", resetPasswordController, {
  middleware: [tokenConsumeThrottleMiddleware()], // 10 failures / 15m per IP
});
```

`resetPassword` writes the password, then calls `authService.revokeAllTokens(user)`: every refresh token is revoked and every access token deleted, which also kills cookie sessions (a cookie holds an access token). It emits `password.reset`; `requestPasswordReset` emits `password.resetRequested`.

**Password hashing.** By default auth saves `hashPassword(plain)` and checks it with `verifyPassword`, the same check login uses. If your model hashes on save (`useHashedPassword()`), that first write gets hashed twice and fails the check, so auth saves the plaintext and lets your transformer hash it once. If neither write passes the check, it throws. Plaintext is never the first thing written. To write it yourself, set `auth.passwordReset.setPassword`.

## Throttling

Both presets wrap `loginThrottleMiddleware` and accept its options:

| Preset | Tracks | Counts | Default |
| --- | --- | --- | --- |
| `tokenIssueThrottleMiddleware` | email + IP | **every** request (a reset request's success is the anti-enumeration answer, so failure-aware counting would never trip) | 3 / 1h, 1h lock |
| `tokenConsumeThrottleMiddleware` | IP | failures only, cleared on success | 10 / 15m, 15m lock |

## Configuration (`src/config/auth.ts`)

```ts
const authConfigurations: AuthConfigurations = {
  // ...
  verification: {
    expiresIn: "24h",
    field: "emailVerifiedAt",
    url: (token) => `${env("APP_URL")}/verify-email?token=${token}`,
    notification: myVerificationNotification, // optional replacement
  },
  passwordReset: {
    expiresIn: "60m",
    identifierField: "email",
    url: (token) => `${env("APP_URL")}/reset-password?token=${token}`,
    notification: myResetNotification,
    setPassword: async (user, plain) => { /* optional */ },
  },
  oneTimeToken: { model: AppOneTimeToken }, // optional model override
};
```

The default notifications are `defineNotification` objects (`type: "auth.email-verification"` / `"auth.password-reset"`, `via: ["mail"]`). To replace one, pass anything with a `send(user, { token, expiresAt, url? })` method, for example your own `defineNotification<OneTimeTokenNotificationData>({...})`. `notifications` still has to be installed and configured.

## Gotchas

- **Without `url` config, the email contains the raw token**, not a link. Set `url` for anything user-facing.
- **Timing isn't equalised.** An unknown email skips the database write and the send, so the response can come back measurably faster. The throttle limits probing, but it doesn't hide the timing difference.
- **Channel send failures don't throw.** `@warlock.js/notifications` only rethrows configuration errors (such as a missing `mail` channel). An SMTP failure goes to its `failed` event, so observe it there.
- `auth.cleanup` does not purge `one_time_tokens` yet. Expired rows are harmless but accumulate.

## See also

- [`@warlock.js/auth/register-user/SKILL.md`](@warlock.js/auth/register-user/SKILL.md) — where `sendEmailVerification` is usually called
- [`@warlock.js/auth/throttle-login-attempts/SKILL.md`](@warlock.js/auth/throttle-login-attempts/SKILL.md) — the underlying throttle
- [`@warlock.js/notifications/configure-notifications/SKILL.md`](@warlock.js/notifications/configure-notifications/SKILL.md) — mail channel setup
