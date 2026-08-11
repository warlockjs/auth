# Auth — backlog

Findings log, newest first. Captures source bugs, doc/skill drift, and release-quality gaps surfaced while polishing `@warlock.js/auth`. Items marked **FIXED** were resolved in the same pass; items marked **OPEN** need a separate decision or change.

---

## 2026-08-10 — 🔴 `expiresIn` validation (issue #25)

Source report: `plans/2026-08-10-auth-an-unparseable-expiresIn-silently-mints-a-token-with-no-exp-claim.md`.
Measured against `ms@2.1.3` and `fast-jwt@6.2.4` **as installed in this workspace** (the report was written against `fast-jwt@6.3.2`; the difference matters for one sub-claim, noted below).

### FIXED — an unparseable or non-positive `expiresIn` minted a token with no `exp` claim

**Root cause, confirmed.** `auth.service.ts` tested the *raw config string* for truthiness (`expiresInConfig ? ms(expiresInConfig) : ms("1h")`), so `"30dayz"` — truthy, unparseable — skipped the `1h` fallback and reached the signer as `undefined`. The refresh path had no fallback at all. Both `as ms.StringValue` casts were what let arbitrary config text compile against `ms`'s template-literal type; both are gone.

**Proven, before the fix** (temporary evidence spec, deleted after capture):

```
THREW AFTER SIGNING: Invalid time value
jwt.generate called with: {}
AccessToken.issue expiresAt: Invalid Date
RESULT: {"token":"signed-access-token","expiresAt":"2026-08-10T20:23:50.202Z"}
jwt.generate called with: {"expiresIn":0}
 ✓ CURRENT BEHAVIOUR with accessToken.expiresIn = '30dayz' > signs a token with expiresIn undefined and persists an Invalid Date
 ✓ CURRENT BEHAVIOUR with accessToken.expiresIn = '0d' > returns a token whose expiry is already now — no error at all
```

(`jwt.generate called with: {}` is `JSON.stringify` dropping `undefined`; the passing assertion was `toHaveBeenCalledWith(expect.any(Object), { expiresIn: undefined })`.)

**Two corrections to the report, both measured:**

1. **In this source tree (4.11.0) the access path is not fully silent for `"30dayz"`.** `generateAccessToken` ends with `expiresAt.toISOString()`, and `Invalid Date.toISOString()` throws `RangeError: Invalid time value` — *after* the no-`exp` token was signed and *after* the row was persisted with `Invalid Date`. The caller sees an opaque error naming nothing; the corrupt row survives. The reported "login succeeds silently" symptom matches the published 4.10.0 esm, which returned the `Date` object directly.
2. **`"0d"` is worse than "an already-expired token".** `fast-jwt` only validates `expiresIn` when it is truthy (`signer.js:234`), so `0` skips validation *and* the `exp` claim is omitted entirely (`signer.js:97`). `"0d"` therefore mints the same never-expiring credential as `"30dayz"`, but silently and with a row that claims it expired immediately. This is the case a naive undefined-only guard passes.
3. Ancillary: `ms(2592000)` returns the **string** `"43m"`, not a number — `ms` formats numbers rather than parsing them. The 43-minute figure is right; the mechanism is a string that turns `Date.now() + expiresIn` into an `Invalid Date`.

**The fix.** `authConfig.accessToken.expiresInMs()` / `refreshToken.expiresInMs()` (in `auth-config.ts`) parse and validate, throwing `auth.<key>: <value> is not a valid ms duration — …`. Both service call sites now use them, and the refresh path validates *before* `enforceMax`, so a bad value can't revoke a user's oldest session on its way to failing. A silent substitution of `1h` was rejected as the fix: it trades one unchosen lifetime for another, just as quietly.

**Placement.** Validation lives in `auth-config.ts` (config-resolution layer) but fires at first token issue, not at boot. Earlier is not reachable from inside this package: `auth` has no boot hook of its own — `src/index.ts` is pure re-exports and config is read lazily through `config.key` from `@warlock.js/core`. A true boot-time gate needs a hook in `core/`, which was out of fence for this change. **OPEN:** consider a `validateAuthConfig()` export an app can call from its bootstrap, or a core-level config-validation hook, so a typo fails the deploy rather than the first login.

**Behaviour change, deliberate:** an empty-string `expiresIn` (e.g. `env("JWT_TTL")` with the variable unset) and a bare number now throw instead of silently falling back / corrupting the expiry. Documented in `CHANGELOG.md`, `README.md`, and the `auth-basics` / `manage-tokens` skills.

### FIXED (issue #27) — nothing ever rejected a token that has no `exp` claim, and the persisted `expires_at` was never enforced

Not folded into the fix above; it is the reason the defect was exploitable rather than merely wrong.

Measured directly against `fast-jwt@6.2.4`:

```
payload: {"id":1,"tokenType":"access","iat":1786393444}
verify (now): {"id":1,"tokenType":"access","iat":1786393444}
verify (+100y): {"id":1,"tokenType":"access","iat":1786393444}
```

`jwt.verify` passes no `maxAge` and no `clockTimestamp`, so a token minted without `exp` verifies **indefinitely** — the report's untested suspicion is correct. Worse, `authMiddleware` (`src/middleware/auth.middleware.ts:47-61`) checks only that the token *row still exists*; it never compares `expires_at` to now. The only thing that removes such a row is the out-of-band `auth.cleanup` command (`expires_at < new Date()`), and a row whose `expires_at` is `Invalid Date` never satisfies that predicate — so it is never purged either.

**Action to decide (not taken here):** either have `authMiddleware` reject a decoded token with no `exp`, or have it enforce the persisted `expires_at`. Both are policy changes beyond the scope of #25.

---

## 2026-08-11 — 🔴 the other half of #25: tokens already issued (issue #27)

Source: the OPEN item above. #25 stopped never-expiring tokens being **minted**; it did nothing about the ones already **issued**. Three parts, all shipped in 4.12.0.

### Red evidence, captured before any change (temporary probe specs, deleted after capture)

```
ms(NO_EXPIRATION="100y") = 3155760000000 (number)
NO_EXPIRATION token claims: {"id":1,"iat":1786418660,"exp":4942178660}
exp - iat = 3155760000 seconds

payload:        {"id":1,"tokenType":"access","iat":1786418660}
verify (+100y): {"id":1,"tokenType":"access","iat":1786418660}

row expires_at        = 2025-08-11T03:24:20.094Z
response.unauthorized called: 0 time(s)
request.user          = {"id":1,"userType":"user"}

purgeExpired removed: 1
genuinely-expired destroyed: 1
poisoned destroyed:          0
poisoned expires_at:         Invalid Date
```

All three claims in the source report reproduce against `fast-jwt@6.2.4` / `ms@2.1.3` as installed.

**Part 1 — reject a token with no `exp`.** `requiredClaims: ["exp"]` on both `jwt.verify` and `jwt.verifyRefreshToken`, unioned with (never replaced by) a caller's own `requiredClaims`. The precondition was checked rather than assumed: `NO_EXPIRATION` (`"100y"`) produces a **real** `exp` ≈ a century out, so no supported configuration wants a token without one, and the rejection costs nobody a legitimate use.

Placed on *verify*, not on issue: the tokens in question were minted by a version that no longer runs, so a guard on the issue path reaches none of them.

**Part 2 — enforce the persisted `expires_at`.** `AccessToken.isExpired` (new) is consulted by `authMiddleware`, which previously asserted only that the row existed. Both models' `isExpired` **fail closed**: a missing or unparseable expiry counts as expired. `RefreshToken.isExpired` previously answered `false` for a missing `expires_at` ("never expires") — that pinned behaviour was deliberately flipped, since it granted an unlimited life to exactly the malformed rows. The dead row is deleted on rejection.

**Part 3 — remediation: `warlock auth.purge-never-expiring` (+ `--dry-run`).** Chosen over a migration or documented SQL, for reasons that came out of measurement rather than preference:

- **A date predicate cannot express the target.** `Invalid Date` compares `false` against every date, so no `WHERE` reaches such a row.
- **The definitive signal is not in a column.** "This token has no `exp`" lives inside the JWT string. The command decodes the stored token (no signature check — it reads claims, not trust); SQL cannot.
- **The stores disagree about what the row even looks like** (both measured here, in isolation, from the installed drivers):
  - `bson` serialises an `Invalid Date` to **epoch 0** → a MongoDB row reads `1970-01-01T00:00:00Z`, which *is* purgeable by `expires_at < now` and *is* rejected by part 2.
  - `pg`'s `prepareValue` serialises it to the literal `0NaN-NaN-NaNTNaN:NaN:NaN.NaN+NaN:NaN`, which a `timestamp` column rejects → the `INSERT` most likely failed and no row was written at all (the token was still signed and handed to the client; with no row, the middleware rejects it).

  **This is a correction to the framing in the source report.** "Rows with an `Invalid Date` accumulate permanently" is true of the in-memory model and of any store that round-trips a NaN date, but was *not* demonstrated for either supported driver as installed. Not verified end-to-end against a live MongoDB or Postgres — the harnesses in `tests/integration/**` need real servers. The remediation is scoped to be correct either way: it selects on the token's missing `exp` **or** an unusable `expires_at`, so it finds the poisoned credential regardless of which shape the date took.

The CHANGELOG carries a **Remediation** section naming who is affected, what to run, and per-store queries an operator can run **without deploying anything** — the owner's stated preference, honoured for the row-level shapes; the `exp`-claim check is only reachable from code, and that is stated there rather than glossed.

**Suite:** 158 → 200 tests, 14 files, all green. One test was replaced rather than added: `jwt.spec.ts` "does not stamp an exp claim when expiresIn is omitted" asserted that a no-`exp` token *verifies*, which is now the defect. Twelve other specs that minted tokens without `expiresIn` were given a lifetime — they were describing a token this package can no longer issue.

**OPEN — carried forward from #25, untouched:** validating auth config at **boot** rather than at first token issue still needs a hook in `core/` (out of fence; #29-adjacent).

**OPEN — `tokenHasExpClaim` decodes without verifying.** A row whose token cannot be decoded at all answers "no `exp`" and is therefore purged. That is the safe direction (an undecodable token cannot authenticate anyway), but it means the remediation deletes garbage rows as well as poisoned ones. Deliberate; noted in case an operator expects a purely conservative tool.

---

## 2026-06-01 — Release-polish pass (skills + tests + docs)

### OPEN — `tsconfig.json` was deleted from the package root

`auth/tsconfig.json` is gone (shows as `D tsconfig.json` in git status). Without it there is no `tsc --noEmit` gate for the package, so type regressions can't be caught in CI. The sibling packages keep a `tsconfig.json`. **Action:** restore a `tsconfig.json` before publishing (copy the shape from a sibling like `cache/tsconfig.json`). Left untouched here — out of scope for a docs/tests/skills pass and not behavior-preserving to invent.

### FIXED — refresh-secret fallback now implemented (was: documented but not implemented)

`src/services/jwt.ts` `getRefreshSecretKey()` previously returned `config.key("auth.jwt.refresh.secret")` with **no fallback**, so an omitted refresh secret made `key` `undefined` and `fast-jwt`'s `createSigner` threw on every refresh-token op. This contradicted the docs:
- `src/contracts/types.ts:68-69` — *"Separate secret for refresh tokens … If not provided, falls back to main JWT secret"*.

Resolved via option **(A)** — implemented the documented fallback: `getRefreshSecretKey = () => (config.key("auth.jwt.refresh.secret") || getSecretKey()) as string`. When the refresh secret is unset/empty, refresh tokens are signed/verified with the main JWT secret; a configured refresh secret is still used as-is. The pinning test in `src/services/jwt.spec.ts` was flipped to assert the fixed behavior (*"falls back to the main JWT secret when no refresh secret is configured"*). Skill `manage-tokens` updated to document the fallback. Full suite green via `cd "@warlock.js" && npx vitest run --root auth`.

### FIXED — skill/doc drift: route middleware attached positionally

Every route example used the **wrong call shape**: `router.get(path, authMiddleware(...), controller)`. The core router signature is `router.METHOD(path, handler, options)` where `handler: RequestHandler | [controller, method]` and middleware lives in `options.middleware: Middleware[]` (verified: `core/src/router/router.ts:276`, `core/src/router/types.ts:17,23`; canonical usage in `core/skills/use-middleware/SKILL.md`). Passing `authMiddleware(...)` positionally makes it the route *handler* and silently drops the real controller — the gate never runs.

Corrected to `router.METHOD(path, controller, { middleware: [authMiddleware(...)] })` across:
- Skills: `protect-routes`, `customize-user-type`.
- Docs: `getting-started/01-introduction.md`, `getting-started/04-first-protected-route.md`, `reference/api.md`, `guides/protect-routes.md`, `guides/customize-user-type.md`, `guides/handle-login-and-logout.md`, `recipes/logout-everywhere.md`.

### FIXED — skill/doc drift: route groups used a non-existent `group.use()` API

Examples used `router.group("/admin", (group) => { group.use(...); group.get(...) })`. The real signature is `router.group({ prefix, middleware }, () => { router.get(...) })` — first arg is an options object, the callback takes no args, and there is no `group.use()` (verified: `core/src/router/router.ts:457`). Corrected in skill `protect-routes` and docs `guides/protect-routes.md`, `recipes/list-active-sessions.md`.

### FIXED — skill drift: `run-auth-commands` used non-existent `defineCommand`

The custom-command example imported `defineCommand` from `@warlock.js/core` and used a `handler()` key. Core exports `command(options)` with an `action` key (verified: `core/src/cli/cli-command.ts:260`; the bundled `auth-cleanup-command.ts` uses `command({ ..., action })`). Rewrote the example to a `command({ name, description, preload, action })` factory and updated the trigger keyword in the skill frontmatter.

### FIXED — skill drift: `response.json` / `response.created` are not Response methods

- `protect-routes/SKILL.md` used `response.json({...})` → corrected to `response.success({...})`.
- `register-user/SKILL.md` used `response.created({...})` (x2) → corrected to `response.successCreate({...})`.

Verified against `core/src/http/response.ts`: the helpers are `success`, `successCreate`, `conflict`, `unauthorized`, `notFound`, `badRequest`, `forbidden`, `send` — there is no `json` or `created`.

### FIXED — skill/doc drift: `request.input()` called with no argument

`request.input(key)` requires a key (`core/src/http/request.ts:718`); calling `request.input()` then destructuring throws. Corrected to `request.all()` (`core/src/http/request.ts:859`) in `register-user/SKILL.md`, `docs/.../guides/register-user.md`, and `docs/.../getting-started/04-first-protected-route.md`.

### FIXED — skill wording: `authEvents` mislabelled an `EventEmitter`

`handle-login-and-logout/SKILL.md` called `authEvents` "an `EventEmitter`". It is a typed wrapper over `@mongez/events` (`on`/`subscribe`/`emit`/`trigger`/`off`/`unsubscribeAll`). Reworded to "a type-safe event bus (over `@mongez/events`)".

### FIXED — test infra: per-package vitest config resolved aliases against the wrong CWD

`auth/vitest.config.ts` used `path.resolve("./../core/src/index.ts")` (process-CWD relative). Run from the monorepo root with `--root auth`, that resolved to `node/core/...` (one level too high), so `@warlock.js/*` imports failed and **both** existing spec files errored at import. Switched to `resolve(__dirname, "../core/src/index.ts")` (matching the `cache` package convention). Behavior-preserving config fix; the two pre-existing specs now pass.

### Added — test coverage (priority gap: package had ~2 spec files)

New/extended specs, all green via `cd "@warlock.js" && npx vitest run --root auth` (6 files, 36 tests):
- `src/services/jwt.spec.ts` (new, 8) — generate/verify round-trip, three-segment token, `exp` claim, foreign-secret rejection, expired-token rejection, refresh round-trip, refresh-vs-access secret isolation, no-refresh-secret throw.
- `src/services/auth-events.spec.ts` (new, 7) — `on`/`emit`, `subscribe`/`trigger` aliases, multi-arg delivery, `off(event)`, `unsubscribeAll`, subscription handle `.unsubscribe()`.
- `src/models/refresh-token/refresh-token.model.spec.ts` (new, 8) — `isExpired` / `isRevoked` / `isValid` truth tables incl. missing-`expires_at` = never-expires.
- `src/services/auth.service.spec.ts` (new, 4) — `buildAccessTokenPayload` claim shape + `created_at` window; `hashPassword` / `verifyPassword` delegation in `(plain, hash)` order.
- `src/middleware/auth.middleware.spec.ts` (extended +4) — missing access-token row, deleted-user destroy path, verify-throws catch path (clears current user), unknown-user-type → no model → reject.

### Note — docs-review findings from 2026-05-29 already resolved in current tree

`domains/discussions/2026-05-29-docs-review-findings.md` flagged two source bugs that are **already fixed** in the working tree:
- `authMiddleware([])` no longer lets unauthenticated requests through — the middleware now rejects any request without `authorizationValue` unconditionally (`src/middleware/auth.middleware.ts:31`).
- `confirmPassword` now calls `verifyPassword(password, this.string("password")!)` = `(plain, hash)`, the correct order (`src/models/auth.model.ts:90`, matching `core/src/encryption/password.ts:83`).

The published docs + skills already describe the corrected behavior. No further action.
