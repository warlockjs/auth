# Changelog — @warlock.js/auth

All notable changes to `@warlock.js/auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `@warlock.js/*` packages are released in lockstep — every package shares the same version number, so a version below may list only the changes that affected this package.

## 4.2.11

### Changed

- Bumped `@mongez/reinforcements` to 3.3.0

## 4.2.10

### Fixed

- `@mongez/copper`, `@mongez/events`, and `@mongez/reinforcements` are now regular `dependencies` instead of `peerDependencies` — matching every other framework package. They're framework-internal utilities your app never imports directly, so declaring them as peers forced consumers to install them and produced `unmet peer dependency` warnings on install. They now resolve transitively and silently.

## 4.2.0

### Added

- `loginThrottleMiddleware` — failure-aware brute-force / credential-stuffing protection that counts only failed logins, resets on a successful one, locks per-account and per-IP, and rejects pre-controller with `429` (cache-backed, fails open on a cache outage). Adds `AuthErrorCodes.TooManyAttempts` (`EC004`).
- `accessToken` / `refreshToken` configuration blocks, making a separate refresh-token secret first-class.
- Overridable token storage — register a custom model under `config.auth.accessToken.model` / `config.auth.refreshToken.model` and `.extend()` the exported `accessTokenSchema` / `refreshTokenSchema` to add columns (e.g. a multi-tenant `organization_id`). Models own issuance through `issue()` and expose named statics, so the service hard-codes no column names.
- `tokenType` (`access` | `refresh`) claim, stamped on issue and verified on read, so an access token can no longer be presented as a refresh token.
- `expires_at` on access tokens; `warlock auth.cleanup` now purges expired access tokens as well as refresh tokens.

### Fixed

- Default access-token lifetime was ~3.6 seconds (a numeric `expiresIn` interpreted as milliseconds) and is now **1 hour**.
- Targeted revocation queried `userId` instead of the `user_id` column, so logout and refresh-token removal threw on Postgres and silently no-oped on MongoDB. The service now routes every token query through named model statics, so no column name is hard-coded.
- Token deletions were fire-and-forget inside `Promise<void>` methods (false success for callers, uncatchable rejections) and are now awaited.
- The route middleware matched on `userType` instead of the `user_type` column.
- `revokeAllTokens` / `revokeTokenFamily` reported an empty set — a re-query on `revoked_at: null` after the update matched nothing — so the `token.revoked` / `token.familyRevoked` events never fired. The revoked rows are now captured before revocation.
- A throwing synchronous auth-event listener no longer turns a completed login into a `500`.

### Security

- `warlock jwt.generate` now derives `JWT_SECRET` / `JWT_REFRESH_SECRET` from a CSPRNG (`Random.token`) instead of `Math.random()`-backed `Random.string`.
- Refresh-token rotation is atomic: a guarded conditional `UPDATE` means two concurrent rotations of the same token can never both succeed, and a replayed token revokes its entire family.

### Deprecated

- The `auth.jwt.*` configuration block (`jwt: { secret, expiresIn, refresh }`). Use `accessToken` / `refreshToken` instead — the legacy shape is still read and mapped forward with a one-time deprecation warning.

### Removed

- Unread `access_tokens` columns `is_active` and `last_access`.
- The unused `auth.password.salt` configuration key.

## 4.1.15

- Baseline — per-package changelog tracking starts at this version.
