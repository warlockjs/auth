---
name: manage-tokens
description: 'Token lifecycle — generateAccessToken, createRefreshToken, createTokenPair, refreshTokens (with rotation + replay detection), revokeAllTokens, revokeTokenFamily, cleanupExpiredTokens, getActiveSessions. Triggers: `createTokenPair`, `refreshTokens`, `revokeTokenFamily`, `cleanupExpiredTokens`, `getActiveSessions`, `jwt.generate`, `jwt.verify`, `AccessToken`, `RefreshToken`; "rotate refresh tokens", "detect token replay", "logout from all devices", "list active sessions", "clean up expired tokens"; typical import `import { authService, jwt } from "@warlock.js/auth"`. Skip: login flow — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; CLI cleanup — `@warlock.js/auth/run-auth-commands/SKILL.md`; competing libs `jsonwebtoken`, `jose`, `fast-jwt`.'
---

# Manage tokens

Tokens are persisted Cascade models. Issuing a token writes a row. Verification checks the row exists. Revocation deletes / marks-revoked. This gives you JWT's stateless verification + statelful revocation.

## Token shapes

```ts
type AccessTokenOutput = { token: string; expiresAt: string };
type RefreshTokenOutput = { token: string; expiresAt: string };

type TokenPair = {
  accessToken: AccessTokenOutput;
  refreshToken?: RefreshTokenOutput;   // omitted if config.auth.refreshToken.enabled = false
};
```

## Issuing tokens

```ts
import { authService } from "@warlock.js/auth";

// Just an access token (rare — usually use createTokenPair)
const access = await authService.generateAccessToken(user);

// Just a refresh token
const refresh = await authService.createRefreshToken(user, deviceInfo);

// Both — the everyday case
const pair = await authService.createTokenPair(user, deviceInfo);
```

`createTokenPair` is the typical issuance path. It respects `config.auth.refreshToken.enabled` — if disabled, returns only `accessToken`.

## Refresh with rotation — `refreshTokens`

```ts
const next = await authService.refreshTokens(oldRefreshToken, deviceInfo);
// next: TokenPair | null
```

What happens internally:

1. Verify the JWT signature on the old refresh token.
2. Find the row in `RefreshToken` — must exist + not be revoked.
3. Look up the user via `config.auth.userType[token.userType]`.
4. **Rotation** (default — `config.auth.refreshToken.rotation = true`): revoke the old refresh token, create a new pair from the same `family_id`.
5. **No rotation**: mark the old as "used" but keep it valid.

**Replay detection.** If the old refresh token is presented again after rotation (already revoked but still in the DB):

```ts
// Inside refreshTokens, on a revoked-token presentation:
await authService.revokeTokenFamily(refreshToken.get("family_id"));
```

Every refresh token in the same family is revoked. Pattern: a leaked refresh token is used by both legitimate user and attacker — the second use triggers the revoke, both sides get kicked.

## Family — the rotation chain

```
login            → creates family X — refresh token A in family X
refresh (A)      → revokes A; creates B in family X
refresh (B)      → revokes B; creates C in family X
refresh (A again)→ A is revoked → revoke family X entirely
```

The family ties together "successive rotations of one session." Logout of one device kills only that device's family — other devices keep their own families.

## Listing active sessions

```ts
const sessions = await authService.getActiveSessions(user);

for (const session of sessions) {
  session.get("device_info");     // { userAgent, ip, deviceId? } if provided at login
  session.get("created_at");
  session.get("expires_at");
}
```

Use this for "active sessions" UIs. Revoke a specific session by calling `.revoke()` on the `RefreshToken` instance.

## Removing tokens

```ts
// Specific access token
await authService.removeAccessToken(user, accessTokenString);

// Specific refresh token (via the RefreshToken instance)
const rt = await RefreshToken.findByToken(refreshString);
await rt?.revoke();

// All access tokens for a user
await authService.removeAllAccessTokens(user);

// Everything — access + refresh + family
await authService.revokeAllTokens(user);

// A specific family
await authService.revokeTokenFamily(familyId);
```

## Max refresh tokens per user

```ts
// In config.auth.refreshToken:
{
  maxPerUser: 5,   // default
}
```

When issuing a new refresh token, the service counts active tokens for the user and revokes the oldest until count < `maxPerUser`. Pattern: limits how many simultaneous sessions a user can hold; prevents an attacker who got a token from gradually accumulating many.

## Expired-token cleanup

```ts
const cleaned = await authService.cleanupExpiredTokens();
// Returns: number of expired refresh tokens removed (also purges expired access-token rows).
// Fires "token.expired" event per token + "cleanup.completed" with the count.
```

Run this periodically via the scheduler:

```ts
import { scheduler, job } from "@warlock.js/scheduler";
import { authService } from "@warlock.js/auth";

scheduler.addJob(
  job("auth-cleanup", () => authService.cleanupExpiredTokens())
    .daily()
    .at("03:00"),
);
```

Or use the bundled CLI command — see [`@warlock.js/auth/run-auth-commands/SKILL.md`](@warlock.js/auth/run-auth-commands/SKILL.md).

## JWT helpers

For low-level JWT signing/verification (outside the authService flow):

```ts
import { jwt } from "@warlock.js/auth";

const token = await jwt.generate(payload, { expiresIn: "1h" }); // string or ms; a bare number is milliseconds
const decoded = await jwt.verify(token);

const refreshToken = await jwt.generateRefreshToken(payload, { expiresIn });
const decodedRefresh = await jwt.verifyRefreshToken(refreshToken);
```

The package signs access and refresh tokens with independent secrets — `config.auth.accessToken.secret` and `config.auth.refreshToken.secret`. Setting a distinct `refresh.secret` is recommended: it prevents an access-token compromise from forging refresh tokens (and vice versa). The refresh secret is **optional** — when `config.auth.refreshToken.secret` is unset, refresh tokens fall back to the main `config.auth.accessToken.secret`, so refresh works out of the box without a second secret.

## Things NOT to do

- Don't use raw JWT libraries directly. The package handles signing, verification, secret loading, and the access/refresh split.
- Don't disable rotation (`config.auth.refreshToken.rotation = false`) unless you genuinely understand the tradeoff — you lose replay detection.
- Don't increase `maxPerUser` to a huge number "to be safe." Each active refresh token is a revocation surface; fewer simultaneous tokens means less attack surface.
- Don't manually delete `AccessToken` rows in a service. The user might be hitting a request mid-revoke and get an inconsistent state. Use the `authService` helpers.

## See also

- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — full login/logout flow that uses these primitives
- [`@warlock.js/auth/run-auth-commands/SKILL.md`](@warlock.js/auth/run-auth-commands/SKILL.md) — the bundled cleanup command
- [`@warlock.js/scheduler/scheduler-basics/SKILL.md`](@warlock.js/scheduler/scheduler-basics/SKILL.md) — scheduling cleanup
