# Auth — backlog

Findings log, newest first. Captures source bugs, doc/skill drift, and release-quality gaps surfaced while polishing `@warlock.js/auth`. Items marked **FIXED** were resolved in the same pass; items marked **OPEN** need a separate decision or change.

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
