---
name: overview
description: 'Front-door orientation for `@warlock.js/auth` — JWT authentication for Warlock apps: the `Auth` base model, `authMiddleware` route gate, `authService` (login / logout / refresh with token rotation + replay detection), persisted AccessToken + RefreshToken, multi-user-type support, auth lifecycle events, and two CLI commands. Coupled to `@warlock.js/core`. TRIGGER when: code imports anything from `@warlock.js/auth`; user asks "what does @warlock.js/auth do", "how do I add login to my Warlock app", "JWT auth in Warlock", "protect a route", "multiple user types / admin + user", "refresh token rotation"; package.json adds `@warlock.js/auth`. Skip: specific task already known — load the matching task skill directly (`auth-basics`, `protect-routes`, `handle-login-and-logout`, `register-user`, `manage-tokens`, `customize-user-type`, `run-auth-commands`); non-Warlock apps (this package depends on core); session-cookie auth (this is JWT/token-based).'
---

# `@warlock.js/auth` — overview

JWT authentication for Warlock apps. You get a base `Auth` model your user types extend, an `authMiddleware` route gate, an `authService` that runs login/logout/refresh (with refresh-token rotation and replay detection), persisted access + refresh tokens, multi-user-type support, lifecycle events, and two bundled CLI commands.

Coupled to `@warlock.js/core` — you're inside a Warlock project before this package makes sense.

## When to reach for it

- You're building a Warlock app that needs login, protected routes, and token-based sessions.
- You need **multiple user types** (admins + regular users, or client/vendor/staff personas) gated separately on the same auth system.
- You want refresh-token **rotation + replay detection** out of the box rather than hand-rolling token security.

Skip if you're not on `@warlock.js/core` (the package depends on it), or if you need session-cookie auth rather than JWTs.

## The mental model in one paragraph

Your user model extends the `Auth` base model and declares its `userType`. A login flows through `authService.login(Model, credentials, deviceInfo?)`: it verifies the password, issues an access + refresh token pair (persisted as `AccessToken` / `RefreshToken` records), and fires events. `authMiddleware(allowedUserType)` gates routes — the argument is required and always requires a valid token: `[]` allows any authenticated user, a user-type argument restricts to those types (401 otherwise). There is no anonymous mode; public routes simply omit the middleware. Refresh rotates the refresh token and detects replay by revoking the whole token family. CLI commands generate the JWT secret and clean up expired tokens.

## Skills index

Nine task skills. Most apps need `auth-basics` + `protect-routes` + `handle-login-and-logout`.

### Foundations

#### [`auth-basics`](@warlock.js/auth/auth-basics/SKILL.md)
Start here. The `Auth` base model, `authMiddleware` gate, `authService` (login/logout/refresh), AccessToken + RefreshToken persistence, multi-user-type support.

### The flows

#### [`handle-login-and-logout`](@warlock.js/auth/handle-login-and-logout/SKILL.md)
`authService.login(Model, credentials, deviceInfo?)` — verify password, issue the token pair, fire events. `authService.logout(user, accessToken?, refreshToken?)` — revoke tokens. For your `POST /login` and `POST /logout` controllers.

#### [`register-user`](@warlock.js/auth/register-user/SKILL.md)
Sign up a new user and issue the first token pair — `User.create({ ...password: await hashPassword(plain) })` then `authService.createTokenPair(user)`. For `POST /register`.

#### [`protect-routes`](@warlock.js/auth/protect-routes/SKILL.md)
`authMiddleware(allowedUserType)` — the argument is required and always requires a valid token: `[]` allows any authenticated user, a user-type argument restricts to those types. Sets `request.user` + `request.decodedAccessToken`, responds 401 on failure.

### Going deeper

#### [`manage-tokens`](@warlock.js/auth/manage-tokens/SKILL.md)
The token lifecycle — `generateAccessToken`, `createRefreshToken`, `createTokenPair`, `refreshTokens` (rotation + replay detection), `revokeAllTokens`, `revokeTokenFamily`, `cleanupExpiredTokens`, `getActiveSessions`. For custom login/registration, token revocation, "logout everywhere", and scheduled cleanup.

#### [`customize-user-type`](@warlock.js/auth/customize-user-type/SKILL.md)
Support multiple user types in one system — each `Auth` subclass overrides `userType`, `config.auth.userType.<slug>` maps the slug to a model class, `authMiddleware("admin")` / `authMiddleware(["admin", "staff"])` gates per type.

#### [`customize-token-storage`](@warlock.js/auth/customize-token-storage/SKILL.md)
Override the persisted `AccessToken` / `RefreshToken` models to add columns (multi-tenant `organization_id`), rename, or change storage — extend the model + schema and register it under `config.auth.accessToken.model` / `config.auth.refreshToken.model`.

#### [`throttle-login-attempts`](@warlock.js/auth/throttle-login-attempts/SKILL.md)
Brute-force / credential-stuffing protection — `loginThrottleMiddleware()` counts only failed logins, resets on success, locks per-account + per-IP after a threshold, and rejects pre-controller with 429. Cache-backed, fails open on a cache outage.

#### [`run-auth-commands`](@warlock.js/auth/run-auth-commands/SKILL.md)
Two CLI commands — `warlock jwt.generate` (strong JWT secret → `.env`) and `warlock auth.cleanup` (remove expired refresh tokens). Register via `registerJWTSecretGeneratorCommand()` and `registerAuthCleanupCommand()`.

## What this package deliberately doesn't do

- **Session-cookie auth.** It's JWT/token-based. If you need server-side sessions, this isn't it.
- **OAuth / social login / SSO.** No provider adapters here — wire those at the controller layer and create the user through this package's models.
- **Authorization / roles / permissions (RBAC).** It authenticates (who you are) and gates by user *type*, not fine-grained permissions. Build RBAC on top.
- **Standalone use.** It depends on `@warlock.js/core` for routing, models (Cascade), and config.

## See also

- [`@warlock.js/core/warlock-conventions/SKILL.md`](@warlock.js/core/warlock-conventions/SKILL.md) — the framework auth runs inside (routing, middleware, config).
- [`@warlock.js/cascade/cascade-basics/SKILL.md`](@warlock.js/cascade/cascade-basics/SKILL.md) — the ORM behind the `Auth`, `AccessToken`, and `RefreshToken` models.
- `mongez-agent-kit-authoring-skills` (load via agent-kit sync) — how this `overview/SKILL.md` becomes `.claude/skills/warlock-js-auth-overview/`.
