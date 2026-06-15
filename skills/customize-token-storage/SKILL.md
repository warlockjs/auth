---
name: customize-token-storage
description: 'Override the persisted AccessToken / RefreshToken models to add columns (multi-tenant `organization_id`, device metadata), rename, or change storage — without forking the package. Extend the model + `schema.extend(...)`, register it under `config.auth.accessToken.model` / `config.auth.refreshToken.model`, override `issue()` to populate the new column, and add a migration. Triggers: `accessToken.model`, `refreshToken.model`, `AccessToken.issue`, `RefreshToken.issue`, `accessTokenSchema`, `refreshTokenSchema`, "add a column to the token table", "multi-tenant tokens", "organization_id on access token", "override the token model", "custom token storage"; typical import `import { AccessToken, accessTokenSchema } from "@warlock.js/auth"`. Skip: multiple user TYPES (not token storage) — `@warlock.js/auth/customize-user-type/SKILL.md`; the token lifecycle API — `@warlock.js/auth/manage-tokens/SKILL.md`; the config blocks themselves — `@warlock.js/auth/auth-basics/SKILL.md`.'
---

# Customize token storage

The package ships `AccessToken` and `RefreshToken` models and runs the whole token flow through their **named statics** — `issue`, `findByToken`, `activeFor`, `revokeAllFor`, etc. The auth service never references a column name directly; it resolves the *active* model from config. So you change token storage by **registering a subclass**, not by forking.

Reach for this when you need an extra column on the token tables — the common case is a tenant key (`organization_id`) so tokens are partitioned per organization, or richer device metadata.

## The three pieces

A storage override is always three coordinated steps. Miss any one and it breaks — see the strict-mode note below.

### 1. Extend the model + its schema

`accessTokenSchema` / `refreshTokenSchema` are exported so you compose them with `.extend(...)` instead of re-declaring the base shape. Override `issue()` to populate your new column (the user is in hand there).

```ts title="src/app/auth/models/app-access-token.ts"
import { AccessToken, accessTokenSchema, type Auth } from "@warlock.js/auth";
import { v } from "@warlock.js/seal";

export class AppAccessToken extends AccessToken {
  public static schema = accessTokenSchema.extend({
    organization_id: v.string().exists("Organization", { column: "id" }),
  });

  // populate the tenant key on issue — read it off the authenticating user
  public static issue(user: Auth, token: string, expiresAt: Date) {
    return this.create({
      token,
      user_id: user.id,
      user_type: user.userType,
      expires_at: expiresAt,
      organization_id: user.get("organization_id"),
    });
  }
}
```

Refresh tokens follow the same shape — extend `refreshTokenSchema`, and override `issue(user, token, options)` (`options` is `{ familyId, expiresAt, deviceInfo? }`) the same way, copying the base fields plus your column.

### 2. Register the subclass in config

```ts title="src/config/auth.ts"
import { AppAccessToken } from "app/auth/models/app-access-token";
import { AppRefreshToken } from "app/auth/models/app-refresh-token";

export default {
  userType: { user: User },
  accessToken: {
    model: AppAccessToken,            // ← the override
    secret: env("JWT_SECRET"),
    expiresIn: "1h",
  },
  refreshToken: {
    model: AppRefreshToken,           // ← the override
    secret: env("JWT_REFRESH_SECRET"),
    expiresIn: "30d",
  },
};
```

From here the service, the middleware, and every `authService` helper transparently use your model — `findByToken`, `revokeAllFor`, `enforceMax`, and the rest all run against your columns.

### 3. Add the column to the migration

The new column needs a real database column. Add it to your token-table migration (the FK + index match your `User` model's tenant convention):

```ts
this.uuid("organization_id").references("organizations").onDelete("cascade").index();
```

See [`@warlock.js/cascade/write-migration/SKILL.md`](@warlock.js/cascade/write-migration/SKILL.md) for the migration mechanics.

## Why all three — the strict-mode trap

This is the failure people hit. Cascade's `strictMode: "strip"` **drops any field your schema doesn't declare** before the INSERT. So if you set `organization_id` in `issue()` but don't add it to the schema (step 1), the value is silently stripped, and a NOT-NULL `organization_id` column then **fails the INSERT**. The chain is: `issue()` sets it → the *schema* must declare it so it survives → the *migration* must create the column. All three, or nothing.

## You do NOT need read-side scoping

Token lookups go by the unique `token` string (`findByToken`), which already uniquely identifies a row regardless of tenant. So you don't need a tenant-scoped global query scope on the token model — `organization_id` is there for FK cascade-cleanup when an org is deleted, plus partitioning and analytics, not for lookup safety.

## What you're overriding (the contract)

Your subclass inherits and may override these statics — the service calls them, never raw queries:

| Static | Role |
| --- | --- |
| `issue(user, token, …)` | persist a freshly-signed token (override to add columns) |
| `findByToken(token)` | look a row up by its token string |
| `findForUser(user, token)` | a user-scoped lookup (logout) |
| `activeFor(user)` | active, unexpired sessions, newest-first |
| `revokeAllFor(user)` / `revokeFamily(id)` | revoke a set, returning the revoked rows |
| `enforceMax(user, max)` | cap concurrent refresh tokens |
| `purgeExpired()` | delete expired rows (CLI cleanup) |

If you rename a column, override the statics that reference it so they map to your name — the service depends on the method, not the column.

## Things NOT to do

- **Don't set a column without declaring it in `schema.extend(...)`.** `strictMode: "strip"` removes it; a NOT-NULL column then fails the INSERT.
- **Don't add a tenant-scoped global scope to the token model.** Lookups are by unique token; a leaky scope is a cross-tenant exposure risk for no lookup benefit.
- **Don't fork the package to add a column.** Extend + register — you keep receiving package fixes.
- **Don't forget the migration.** The schema declares the field; only the migration creates the database column.

## See also

- [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md) — multiple user *types* (a different axis from token *storage*).
- [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md) — the token lifecycle your statics power.
- [`@warlock.js/cascade/define-model/SKILL.md`](@warlock.js/cascade/define-model/SKILL.md) — extending models and schemas.
