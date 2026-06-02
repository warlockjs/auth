---
name: auth-basics
description: 'Start with @warlock.js/auth — JWT auth, Auth base model, authMiddleware route gate, authService (login / logout / refresh), AccessToken + RefreshToken persistence, multi-user-type support. Triggers: `Auth`, `authMiddleware`, `authService`, `AccessToken`, `RefreshToken`, `authMigrations`; "set up auth in a new app", "which auth skill do I need", "JWT authentication overview", "wire warlock auth"; typical import `import { authMiddleware, authService, Auth, authMigrations } from "@warlock.js/auth"`. Skip: routing — `@warlock.js/auth/protect-routes/SKILL.md`; login — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; competing libs `passport`, `next-auth`, `lucia-auth`, `auth0`.'
---

# Auth basics

JWT-based authentication for Warlock. `Auth` base model + `authMiddleware` gate + `authService` for login/logout/refresh + `AccessToken` / `RefreshToken` persistence + multi-user-type support.

> This skill is the auth **map** — read it first, then load the specific skill for the task.

## Install

```bash
yarn add @warlock.js/auth
```

## Foundations

1. **Users extend `Auth`.** Your `User`, `Admin`, etc. extend the shared base model that knows how to issue tokens and verify passwords. Multiple user types coexist (see [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md)).
2. **`auth.userType.<name>` config maps a user-type slug to the model class.** The middleware uses this to hydrate the right model from a token.
3. **Tokens persist.** Both `AccessToken` and `RefreshToken` are Cascade models — issuing a token writes a row; logout / revoke deletes or marks-revoked. Stateless JWT verification + stateful revocation list.
4. **`authMiddleware(allowedUserType)` gates routes.** The argument is required and a valid token is always required. `[]` → any authenticated user; a user-type → required auth scoped to those types. Public routes omit the middleware entirely.
5. **`authService.login(Model, credentials, deviceInfo?)` is the full happy path.** Verifies credentials, creates token pair (access + refresh), emits events, returns `{ user, tokens }`.
6. **Refresh-token rotation is on by default.** Each refresh consumes the old token and issues new ones from the same "family" — replay detection revokes the family.
7. **JWT secret lives in the env.** Generate with `warlock jwt.generate` (see [`@warlock.js/auth/run-auth-commands/SKILL.md`](@warlock.js/auth/run-auth-commands/SKILL.md)).

## Minimal wire-up

```ts title="warlock.config.ts"
import {
  authMigrations,
  registerAuthCleanupCommand,
  registerJWTSecretGeneratorCommand,
} from "@warlock.js/auth";
import { defineConfig } from "@warlock.js/core";

export default defineConfig({
  cli: {
    commands: [
      registerJWTSecretGeneratorCommand(),
      registerAuthCleanupCommand(),
    ],
  },
  database: {
    migrations: authMigrations,
  },
});
```

```ts title="src/config/auth.ts"
import { User } from "@/app/users/models/user.model";

export default {
  userType: {
    user: User,
    // admin: Admin,  // for multi-user-type
  },
  jwt: {
    secret: env("JWT_SECRET"),
    expiresIn: "1h",
    refresh: {
      enabled: true,
      expiresIn: "30d",
      rotation: true,
      maxPerUser: 5,
    },
  },
};
```

## Pick a skill

| If the task is about… | Load |
| --- | --- |
| Gating routes with `authMiddleware(allowedUserType)`, any-authenticated vs typed access | [`@warlock.js/auth/protect-routes/SKILL.md`](@warlock.js/auth/protect-routes/SKILL.md) |
| `authService.login(...)`, `attemptLogin`, full credentials-to-tokens flow + logout | [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) |
| Token lifecycle — `generateAccessToken`, `createRefreshToken`, rotation, family revocation, max-per-user | [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md) |
| Register a new user + issue tokens in one flow | [`@warlock.js/auth/register-user/SKILL.md`](@warlock.js/auth/register-user/SKILL.md) |
| Multi-user-type apps (`user`, `admin`, `client`), `config.auth.userType.<name>` mapping | [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md) |
| `warlock jwt.generate` + `warlock auth.cleanup` CLI commands | [`@warlock.js/auth/run-auth-commands/SKILL.md`](@warlock.js/auth/run-auth-commands/SKILL.md) |

## Things NOT to do

- Don't write your own JWT signing logic — use `authService` / `jwt` from this package so signature/secret/expiry stay consistent.
- Don't store the JWT secret in the model layer or anywhere user-modifiable. It lives in `.env` only.
- Don't return the raw `User` from a login endpoint without shaping output. Configure `static toJsonColumns` or `static resource` (see [`@warlock.js/cascade/define-model/SKILL.md`](@warlock.js/cascade/define-model/SKILL.md)).
- Don't run `auth.cleanup` from app boot. Schedule it (cron, scheduler) as a periodic task — see [`@warlock.js/scheduler/scheduler-basics/SKILL.md`](@warlock.js/scheduler/scheduler-basics/SKILL.md).
