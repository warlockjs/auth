# Changelog — @warlock.js/auth

All notable changes to `@warlock.js/auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `@warlock.js/*` packages are released in lockstep — every package shares the same version number, so a version below may list only the changes that affected this package.

## 4.2.11

### Changed

- Bumped `@mongez/reinforcements` to 3.3.0

## 4.2.10

### Fixed

- `@mongez/copper`, `@mongez/events`, and `@mongez/reinforcements` are now regular `dependencies` instead of `peerDependencies` — they're framework-internal utilities your app never imports, so declaring them as peers produced `unmet peer dependency` warnings on install.

## 4.2.0

### Added

- `loginThrottleMiddleware` — failure-aware brute-force / credential-stuffing protection: counts only failed logins, locks per-account and per-IP, and rejects pre-controller with `429` (cache-backed, fails open). Adds `AuthErrorCodes.TooManyAttempts` (`EC004`).
- `accessToken` / `refreshToken` configuration blocks, making a separate refresh-token secret first-class.
- Overridable token storage — register a custom model under `config.auth.accessToken.model` / `refreshToken.model` and `.extend()` the exported schemas to add columns (e.g. a multi-tenant `organization_id`).
- `tokenType` (`access` | `refresh`) claim, stamped on issue and verified on read, so an access token can't be presented as a refresh token.
- `expires_at` on access tokens; `warlock auth.cleanup` now purges expired access tokens too.

### Fixed

- Default access-token lifetime was ~3.6 seconds (a numeric `expiresIn` read as milliseconds) and is now **1 hour**.
- Targeted revocation queried `userId` instead of the `user_id` column, so logout / refresh-token removal threw on Postgres and silently no-oped on MongoDB; token queries now route through named model statics.
- Token deletions were fire-and-forget (false success for callers, uncatchable rejections) and are now awaited.
- The route middleware matched on `userType` instead of the `user_type` column.
- `revokeAllTokens` / `revokeTokenFamily` reported an empty set, so `token.revoked` / `token.familyRevoked` never fired; the revoked rows are now captured before revocation.
- A throwing synchronous auth-event listener no longer turns a completed login into a `500`.

### Security

- `warlock jwt.generate` now derives `JWT_SECRET` / `JWT_REFRESH_SECRET` from a CSPRNG (`Random.token`) instead of `Math.random()`.
- Refresh-token rotation is atomic — a guarded conditional `UPDATE` means two concurrent rotations can't both succeed, and a replayed token revokes its entire family.

### Deprecated

- The `auth.jwt.*` configuration block. Use `accessToken` / `refreshToken` instead — the legacy shape is still read and mapped forward with a one-time deprecation warning.

### Removed

- Unread `access_tokens` columns `is_active` and `last_access`.
- The unused `auth.password.salt` configuration key.

## 4.1.15

- Baseline — per-package changelog tracking starts at this version.
