# 2026-05-29 — Auth docs review findings

**Source:** Opus review agent, read-only audit of published Starlight docs vs `@warlock.js/auth/src` + skills.
**Scope of fix (separate session):** apply in lockstep — docs **and** skills + llms regen + build-verify. Read `domains/shared/skills/update-package/SKILL.md` first.
**Note:** this package has **real source bugs**, not just doc drift — at least one needs a framework decision before docs can be made truthful.

Paths:
- Docs: `@warlock.js/docs/src/content/docs/v/latest/auth/`
- Source: `@warlock.js/auth/src/`
- Skills: `@warlock.js/auth/skills/`

## Axis 1 — Documentation quality & drift / SOURCE BUGS

**HIGH — `authMiddleware([])` does NOT mean "required, any user type".** Docs describe three modes: `authMiddleware()` = optional, `authMiddleware([])` = required/any logged-in, `authMiddleware(["type"])` = required/typed. Source proves modes 1 and 2 are **identical**: both produce `allowedTypes = []`, and the gate `if (!allowedTypes.length && !authorizationValue) return;` lets an unauthenticated request through in **both** cases (`auth/src/middleware/auth.middleware.ts:8-18`). There is no "required, any type" mode; required-auth only happens with a non-empty type list.
- Affected docs: `reference/api.md:150,154-156`; `guides/protect-routes.md:23-25,76,132` (the "would have 401'd otherwise" claim is false for `[]`); `guides/handle-login-and-logout.md:132,135`; `guides/customize-user-type.md:91`; `recipes/list-active-sessions.md:79`; `recipes/logout-everywhere.md:29` (these recipes rely on `[]` for required auth → silently allow anonymous).
- **DECISION (framework):** (A) fix docs to the real two-mode behavior, or (B) add a genuine "require any authenticated user" mode to source (`allowedTypes.length === 0 && passed-an-array` ⇒ require a token). Recommend **B** — the documented behavior is what people expect and "require any logged-in user" is a common need. Until decided, the recipes that lean on `[]` are insecure.

**LOW (source bug) — `confirmPassword` args reversed.** Source calls `verifyPassword(this.string("password")!, password)` i.e. `verifyPassword(hash, plain)`, but the signature is `verifyPassword(plain, hash)` (`auth/src/services/auth.service.ts:86,181`). Docs (`essentials/02-user-models.md:108`, `recipes/logout-everywhere.md:61`, `guides/customize-user-type.md`) promise behavior the code mis-implements. Fix the source.

**LOW — `Authenticable` contract stale vs `Auth` class.** `reference/api.md:185-194` copies a contract with `getUserType(): string`, but `Auth` implements `get userType()` (getter), and `generateAccessToken()`/`generateRefreshToken()` return `AccessTokenOutput`/`RefreshToken`, not `Promise<string>` (`auth/src/contracts/auth-contract.ts` vs class). Note the contract is aspirational or omit it.

No invented exports otherwise — `authMigrations`, `jwt.*`, `authEvents.*`, `AuthErrorCodes` (EC001-3), `AccessTokenOutput`/`TokenPair`/`DeviceInfo`/`LoginResult`/`NO_EXPIRATION`, both commands, `access_tokens` columns all verify. `index.mdx` is clean (no stale "still being written"/"Source:" footer). `reference/api.md` still carries inline `Source: …` lines (28-30,40,…) — by-design for an API page; align if global "Source:" purge was intended (LOW).

## Axis 2 — Broken links
**HIGH — cross-package links hit a nonexistent `docs/` subfolder** (Core/Cascade docs live directly under the slug):
- `guides/protect-routes.md:121` → `../../../core/docs/the-basics/http-response.md` (correct: `../../../core/the-basics/http-response.md`)
- `getting-started/01-introduction.md:55` → `../../../cascade/docs/`
- `getting-started/04-first-protected-route.md:64` → `../../../cascade/docs/` (anchor text "cascade/write-migration" isn't a real page; closest `cascade/the-basics/migrations.md`)
*(Same `/docs` bug as Context — fix together.)*
**LOW** — `@warlock.js/scheduler/scheduler-basics` skill-slug refs render as literal text (`guides/manage-tokens.md`, `guides/run-auth-commands.md:111,171`) → convert to real links or drop.
Intra-auth relative links all resolve.

## Axis 3 — Sidebar & DX
Clean. `pkgTopic({ slug: "auth", sections: fullSections })` (`astro.config.mjs:128`); all five dirs exist, every page has `sidebar.order`+`label`. No orphans/dangling.

## Priority
1. **`authMiddleware([])` decision** (security-relevant) — pick A or B, then make docs + recipes truthful.
2. Fix `confirmPassword` source arg order.
3. `/docs` cross-package link sweep (with Context).
