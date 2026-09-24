---
description: "JWT authentication for Warlock apps: login/logout, refresh-token rotation, protected routes, multiple user types. Exports `Auth`, `authService`, `authMiddleware`, `authEvents`, `currentUser`, `loginThrottleMiddleware`, `requireVerifiedEmail`, `GoogleProvider`, `AuthErrorCodes`. Use for: \"log a user in and issue tokens\", \"protect this route\", \"add an admin user type\", \"rate-limit login attempts\", \"verify email / reset password\", \"sign in with Google\". Not this package: general route middleware lives in @warlock.js/core; request-body validation is @warlock.js/seal."
---
# @warlock.js/auth

A user model extends the `Auth` base model and declares a `userType`. `authService.login(Model, credentials)` verifies the password and issues persisted access + refresh tokens; `authMiddleware("user")` gates routes per type. Refresh tokens rotate within a token family, with replay detection. Server-only, and requires `@warlock.js/core`.

## The 80% path
1. Orient with `overview.md`, then `auth-basics.md` for the shape of config and models.
2. Extend `Auth` for your user model: `customize-user-type.md`, `register-user.md`.
3. Log in / out: `handle-login-and-logout.md`; token lifecycle: `manage-tokens.md`.
4. Guard routes: `protect-routes.md`.
5. Harden: `throttle-login-attempts.md`, `verify-email-and-reset-password.md`.
6. Social sign-in: `login-with-providers.md`; CLI (JWT secret, token cleanup): `run-auth-commands.md`.

## Conventions and pitfalls
- Tokens are persisted rows, not stateless JWTs alone; revoking a family invalidates its refresh and access rows.
- `authMiddleware()` with no argument resolves the configured default user type. Be explicit when an app has several.
- Not for session-cookie auth; this is JWT-based.
- Do not value-import this package from client code; `@warlock.js/web` builds refuse it (type-only imports are fine).
- Generate the JWT secret with the bundled command rather than inventing one.
- Custom token storage is a supported extension point: `customize-token-storage.md`.
