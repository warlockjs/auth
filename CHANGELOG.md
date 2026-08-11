# Changelog — @warlock.js/auth

All notable changes to `@warlock.js/auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `@warlock.js/*` packages are released in lockstep — every package shares the same version number, so a version below may list only the changes that affected this package.

## 4.12.0

### Security

> **If you ran 4.11.0 or earlier with an invalid `accessToken.expiresIn` / `refreshToken.expiresIn`, tokens issued in that window may never expire and are still live.** Upgrading stops new ones being minted and stops old ones being accepted — but the rows are still in your database. Run `warlock auth.purge-never-expiring --dry-run` to see them; see **Remediation** below.

- **A token with no `exp` claim is now rejected instead of being accepted forever.** `fast-jwt` has no deadline to check on such a token, so verification simply succeeds — measured against `fast-jwt@6.2.4`, a token with no `exp` verifies unchanged at `clockTimestamp` + 100 years. Both `jwt.verify` and `jwt.verifyRefreshToken` now require an `exp` claim.

  This is deliberately on the *verify* side rather than the issue side: the tokens that lack an `exp` were minted by a version that no longer runs, so a guard on issue would not reach a single one of them. A caller may add to `requiredClaims`, never subtract — `jwt.verify(token, { requiredClaims: ["iat"] })` still requires `exp` too.

- **The persisted `expires_at` is now enforced on every request.** `authMiddleware` previously checked only that the access-token row *existed*; a row whose own expiry had passed still opened the gate, because nothing ever asked. The row is now checked against the clock and deleted on rejection.

  These are two independent defences. The first catches a token whose *claims* carry no deadline; the second catches a token whose *row* says the deadline has passed (a logged-out or expired session whose JWT is still within its own lifetime). Neither subsumes the other.

### Added

- **`warlock auth.purge-never-expiring`** — remediation for rows written by the `expiresIn` defect below. Finds every access- and refresh-token row that can never retire itself, on two independent signals: an `expires_at` that is missing or unparseable, and a persisted token carrying no `exp` claim. Reports `id`, `user_id`, `user_type` and `expires_at` per row (never the token string — it is a live credential until the command removes it), then deletes them. Pass `--dry-run` to report without deleting.

  `auth.cleanup` cannot find these rows and never could: its predicate is `expires_at < now`, and an `Invalid Date` compares `false` against *every* date, so such a row satisfies neither `< now` nor `> now`. It is outside the reach of every date predicate rather than merely wrong. The "no `exp` claim" signal is not in a column at all.

  Exposed programmatically as `authService.findNeverExpiringTokens()` (read-only) and `authService.purgeNeverExpiringTokens()`, and per model as `findNeverExpiring()` / `purgeNeverExpiring()`.

### Remediation — what to run if you were affected

**You were affected if** any deployment ran 4.11.0 or earlier with an `accessToken.expiresIn` / `refreshToken.expiresIn` that `ms` could not parse to a positive number (`"30dayz"`, `"thirty days"`, `"0d"`, `""`, a bare number such as `2592000`). The valid values — `"1h"`, `"7d"`, `"30 days"`, `NO_EXPIRATION`, and the `1h` / `7d` defaults — were never affected.

After upgrading:

```bash
warlock auth.purge-never-expiring --dry-run   # look first
warlock auth.purge-never-expiring             # then revoke
```

Affected users must log in again. To check **without deploying anything**, the row-level shape is visible directly — note that what the bad value lands as depends on the store, and both were measured:

- **MongoDB** — `bson` serialises an `Invalid Date` to **epoch 0**, so the row reads `1970-01-01T00:00:00Z` rather than an invalid value:

  ```js
  db.access_tokens.find({ expires_at: { $lte: new Date(0) } })
  db.refresh_tokens.find({ expires_at: { $lte: new Date(0) } })
  ```

- **PostgreSQL** — `pg` serialises an `Invalid Date` to the literal `0NaN-NaN-NaNTNaN:NaN:NaN.NaN+NaN:NaN`, which a `timestamp` column rejects, so the `INSERT` most likely failed and no row was written (the token was still signed and returned to the client — it is then rejected by the row check, since it has no row). Any rows that did land are visible as:

  ```sql
  SELECT id, user_id, user_type, expires_at FROM access_tokens WHERE expires_at IS NULL OR expires_at <= 'epoch';
  SELECT id, user_id, user_type, expires_at FROM refresh_tokens WHERE expires_at IS NULL OR expires_at <= 'epoch';
  ```

These queries find the row-level shape only. The definitive test — *does the stored token carry an `exp` claim at all* — reads the JWT rather than a column, which is why the command exists and why it is the recommended path.

### Fixed

- **An `expiresIn` the `ms` package cannot parse no longer mints a credential that never expires.** `accessToken.expiresIn: "30dayz"` (or `"thirty days"`, or any truthy-but-unparseable value) made `ms()` return `undefined`, which the signer emitted as a JWT with **no `exp` claim**, alongside a token row whose `expires_at` was `Invalid Date`. The old guard tested the raw config string for truthiness, so the `1h` fallback was unreachable in exactly the case it existed for. `refreshToken.expiresIn` had no fallback at all.

  Both lifetimes are now validated and throw naming the key — before anything is signed, persisted, or capped:

  ```
  auth.accessToken.expiresIn: "30dayz" is not a valid ms duration — use a positive duration string such as "1h", "7d", or NO_EXPIRATION.
  ```

  A silent substitution of the default was deliberately not chosen: it trades one lifetime nobody chose for another, just as quietly.

- **`expiresIn: "0d"` (and any non-positive duration) is rejected too.** It is truthy and parses cleanly to `0`, so it survived any guard that only rejects `undefined` — and `fast-jwt` skips its own validation for `0`, emitting a token with **no `exp` claim** while the persisted row claims it expired immediately.

- A bare number (`expiresIn: 2592000`) is now rejected instead of silently corrupting the expiry. `ms` *formats* numbers rather than parsing them (`2592000` ⇒ `"43m"`), which then poisoned `Date.now() + expiresIn` into `Invalid Date`. Write `"30d"`.

### Changed

- **Potentially breaking:** a JWT with no `exp` claim is rejected by `jwt.verify` / `jwt.verifyRefreshToken`. No supported configuration produces one: an app that wants a token that effectively never expires sets `expiresIn: NO_EXPIRATION` (`"100y"`), which mints a **real** `exp` about a century out (`ms("100y")` ⇒ `3155760000000`; `exp - iat` ⇒ `3155760000` seconds). "No deadline" and "a distant deadline" are different things, and only the second was ever asked for. If you sign tokens with your own signer and feed them to this package's verifier, they must carry `exp`.
- **Potentially breaking:** `RefreshToken.isExpired` now answers `true` for a missing or unparseable `expires_at`; it previously answered `false` ("no expiry recorded ⇒ never expires"). That reading handed an unlimited life to precisely the malformed rows. `expires_at` is `required` in the schema — a row that cannot say when it dies is malformed, not immortal. `AccessToken.isExpired` is new and fails closed the same way.
- **Potentially breaking:** an invalid `accessToken.expiresIn` / `refreshToken.expiresIn` now throws on token issue instead of producing a token with a wrong or absent expiry. Valid configuration is unaffected — `"1h"`, `"7d"`, `"30 days"`, `NO_EXPIRATION` (`"100y"`), the `1h` access default when the key is absent, and the `7d` refresh default all behave exactly as before. An **empty string** (e.g. `env("JWT_TTL")` with the variable unset) now throws rather than falling back; give the env read an explicit default.
- `authConfig.accessToken.expiresInMs()` / `authConfig.refreshToken.expiresInMs()` are the validated accessors token issuers must use; the raw `expiresIn()` accessors are unchanged.
- Removed the `as ms.StringValue` casts on both call sites. They were what let arbitrary config text compile against `ms`'s template-literal type and reach the signer as `undefined`.
- Declares its own test runner and pins it to an exact version (`vitest@4.1.10`). The package is its own repository, so a runner resolved from a workspace root it may not be cloned with is a runner it cannot rely on. The pin is exact rather than a range because the version moved underneath the suite mid-development on an unrelated install — a suite whose runner can change without anyone choosing it proves less than it appears to

## 4.10.0

### Changed

- `protect-routes` documents two things that were previously only discoverable by reading source: that `authMiddleware` gates on **user type by flat string match** and cannot express a permission matrix, role hierarchy, or who-may-act-on-whom — with a worked pointer to `@warlock.js/access` (`gate`, `can`, `definePolicy`) for exactly that; and that auth is **bearer-token by design**, with cookie sessions and CSRF being app-level work rather than an omission

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
