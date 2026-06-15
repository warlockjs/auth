---
name: handle-login-and-logout
description: 'Run the full login flow via authService.login(Model, credentials, deviceInfo?) — verify password, create access + refresh token pair, fire events. Logout via authService.logout(user, accessToken?, refreshToken?) revokes tokens. Triggers: `authService.login`, `authService.logout`, `authService.attemptLogin`, `authService.refreshTokens`, `authService.revokeAllTokens`, `authEvents`; "build a login endpoint", "POST /login controller", "logout from all devices", "verify credentials and issue tokens"; typical import `import { authService, authEvents } from "@warlock.js/auth"`. Skip: token internals — `@warlock.js/auth/manage-tokens/SKILL.md`; sign-up — `@warlock.js/auth/register-user/SKILL.md`; competing libs `passport-local`, `next-auth` credentials.'
---

# Login + logout

`authService` exposes the full flow. Pass the model class so the service knows which user-type to look up.

## Login — `authService.login(Model, credentials, deviceInfo?)`

```ts
import { authService } from "@warlock.js/auth";
import { User } from "@/app/users/models/user.model";

async function loginController(request: Request, response: Response) {
  const result = await authService.login(User, {
    email: request.input("email"),
    password: request.input("password"),
  }, {
    userAgent: request.header("user-agent"),
    ip: request.ip,
  });

  if (!result) {
    return response.unauthorized({ error: "Invalid credentials" });
  }

  return response.success({
    user: result.user,
    tokens: result.tokens,
  });
}
```

The returned shape:

```ts
{
  user: T,                    // your User subclass, hydrated
  tokens: {
    accessToken: { token: string, expiresAt: string },
    refreshToken?: { token: string, expiresAt: string },   // omitted if refresh tokens disabled
  },
}
```

Returns `null` on failure (wrong password, user not found). The service emits `login.attempt` → `login.success` or `login.failed` events as it goes — subscribe via the auth event bus if you need an audit trail.

## What `credentials` looks like

The shape is **arbitrary** — every key except `password` is used as a `where(...)` filter against the model. The password is verified separately via bcrypt.

```ts
// Email + password
authService.login(User, { email: "ada@example.com", password: "..." });

// Username + password
authService.login(User, { username: "ada", password: "..." });

// Phone-based OTP (where password is the OTP hash)
authService.login(User, { phone: "+1...", password: hashedOTP });
```

For lower-level credential verification (just check, don't issue tokens), use `authService.attemptLogin(Model, credentials)` — returns the user or null without creating tokens.

## Device info

The optional `deviceInfo` carries metadata into the refresh token row:

```ts
authService.login(User, credentials, {
  userAgent: request.header("user-agent"),
  ip: request.ip,
  deviceId: "...",          // your client-side device fingerprint
  familyId: "...",          // pre-existing family for token rotation, usually omitted
});
```

Useful for "show active sessions" UIs — see `authService.getActiveSessions(user)`.

## Logout — `authService.logout(user, accessToken?, refreshToken?)`

```ts
async function logoutController(request: Request, response: Response) {
  await authService.logout(
    request.user!,
    request.authorizationValue,        // access token from the Authorization header
    request.input("refreshToken"),     // refresh token from the request body
  );

  return response.success({ message: "Logged out" });
}
```

The contract:
- **Pass the access token** → that specific access-token row is deleted.
- **Pass the refresh token** → that specific refresh-token row is revoked.
- **Omit refresh token** → behavior depends on `config.auth.refreshToken.logoutWithoutToken`:
  - `"revoke-all"` (default) — every refresh token for this user is revoked. Fail-safe.
  - `"error"` — throws. Force the client to send the refresh token.

The `revoke-all` default is the right call for most apps. If a client loses track of the refresh token, logout still works and the user has to log in fresh on every device.

## Logout-everywhere

```ts
await authService.revokeAllTokens(user);
// Revokes every refresh token + deletes every access token for this user.
```

Useful for "logout from all devices" buttons. Fires `token.revoked` per token + `logout.all` once.

## Refresh tokens — `authService.refreshTokens(refreshTokenString, deviceInfo?)`

```ts
async function refreshController(request: Request, response: Response) {
  const tokens = await authService.refreshTokens(
    request.input("refreshToken"),
    { userAgent: request.header("user-agent"), ip: request.ip },
  );

  if (!tokens) {
    return response.unauthorized({ error: "Invalid refresh token" });
  }

  return response.success({ tokens });
}
```

Returns a new token pair or `null` (token expired, revoked, or replay-detected). With rotation enabled (default), the old refresh token is consumed; the new pair stays in the same "family." Replay → revoke the whole family. See [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md).

## Auth events

`authEvents` is a type-safe event bus (over `@mongez/events`) that fires on every meaningful auth moment. Subscribe with `on` / `subscribe`, unsubscribe with `off` / `unsubscribeAll`:

```ts
import { authEvents } from "@warlock.js/auth";

authEvents.on("login.success", (user, tokens, deviceInfo) => { /* audit */ });
authEvents.on("login.failed",  (credentials, reason) => { /* alert on brute force */ });
authEvents.on("logout",        (user) => { /* clear server-side session, if any */ });
authEvents.on("token.refreshed", (user, newPair, oldToken) => { /* track rotation */ });
authEvents.on("cleanup.completed", (count) => { /* metrics */ });
```

Full event list: `login.attempt`, `login.success`, `login.failed`, `logout`, `logout.all`, `logout.failsafe`, `token.created`, `token.refreshed`, `token.revoked`, `token.expired`, `token.familyRevoked`, `session.created`, `session.destroyed`, `cleanup.completed`.

## Things NOT to do

- Don't `authService.login(User, { password })` without other credentials — the password is the secret; the other fields are the lookup. A login with only a password is a logic bug.
- Don't return the password hash in the response. `static toJsonColumns` on the User model should explicitly exclude it.
- Don't store the refresh token in localStorage. Use an httpOnly secure cookie for refresh tokens; the access token can sit in memory.
- Don't issue a new token pair without revoking the old one when rotation is enabled. `refreshTokens` does this for you — don't bypass it.

## See also

- [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md) — token lifecycle, rotation, family revocation
- [`@warlock.js/auth/register-user/SKILL.md`](@warlock.js/auth/register-user/SKILL.md) — sign-up that issues tokens after creation
- [`@warlock.js/auth/protect-routes/SKILL.md`](@warlock.js/auth/protect-routes/SKILL.md) — where the access token gets consumed
