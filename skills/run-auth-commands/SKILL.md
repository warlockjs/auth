---
name: run-auth-commands
description: 'Two bundled CLI commands — warlock jwt.generate (creates strong JWT secret + writes to .env) and warlock auth.cleanup (removes expired refresh tokens). Register via registerJWTSecretGeneratorCommand() and registerAuthCleanupCommand(). Triggers: `registerJWTSecretGeneratorCommand`, `registerAuthCleanupCommand`, `warlock jwt.generate`, `warlock auth.cleanup`, `cleanupExpiredTokens`, `command`; "generate JWT secret", "bootstrap .env JWT_SECRET", "cron job for expired tokens", "schedule auth cleanup"; typical import `import { registerJWTSecretGeneratorCommand, registerAuthCleanupCommand } from "@warlock.js/auth"`. Skip: programmatic cleanup — `@warlock.js/auth/manage-tokens/SKILL.md`; in-process scheduling — `@warlock.js/scheduler/scheduler-basics/SKILL.md`; competing tools `dotenv-cli`, `node-cron`.'
---

# Run auth commands

The package ships two CLI commands. Register them in `warlock.config.ts`; the framework picks them up.

## Register

```ts title="warlock.config.ts"
import {
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
});
```

## `warlock jwt.generate` — JWT secret bootstrap

```bash
yarn warlock jwt.generate
```

Generates a cryptographically strong secret string and writes it to your `.env` as `JWT_SECRET=...` (and `JWT_REFRESH_SECRET=...` if refresh tokens are enabled).

Run it once when setting up a new project. Each developer typically runs it locally; production secrets come from your secret manager (Vault, AWS Secrets Manager, k8s secrets) and bypass this command.

**Don't commit `.env`.** The generated secret should never live in the repo. The command writes to `.env`, which `.gitignore` already excludes in a default Warlock project.

## `warlock auth.cleanup` — expired token sweep

```bash
yarn warlock auth.cleanup
```

Runs `authService.cleanupExpiredTokens()` — deletes every refresh token whose `expires_at` has passed. Fires `token.expired` per token and `cleanup.completed` once.

Schedule it periodically. Two common shapes:

### Via the scheduler

```ts
import { scheduler, job } from "@warlock.js/scheduler";
import { authService } from "@warlock.js/auth";

scheduler.addJob(
  job("auth-cleanup", () => authService.cleanupExpiredTokens())
    .daily()
    .at("03:00")
    .preventOverlap(),
);

scheduler.start();
```

In-process — no shell call. See [`@warlock.js/scheduler/scheduler-basics/SKILL.md`](@warlock.js/scheduler/scheduler-basics/SKILL.md).

### Via system cron

```cron
0 3 * * *  cd /path/to/app && /usr/local/bin/yarn warlock auth.cleanup
```

Out-of-process — works when you don't want the scheduler subsystem running in this service.

## How often?

Once a day is usually enough. The check is cheap (single indexed DELETE on `expires_at < now()`), and refresh tokens that have already expired don't grant access — cleanup is housekeeping, not security.

If you have very-short-lived refresh tokens (1h expiry) and a million-user scale where the table grows fast, cleanup more often (hourly).

## Custom commands

If `auth.cleanup` doesn't cover everything your app needs (e.g. you also want to revoke tokens for inactive users), write your own command and combine the auth service helpers:

```ts
import { command } from "@warlock.js/core";
import { authService } from "@warlock.js/auth";
import { User } from "@/app/users/models/user.model";

export function registerDeepCleanupCommand() {
  return command({
    name: "auth.deep-cleanup",
    description: "Expire stale tokens AND revoke tokens for inactive users",
    preload: {
      env: true,
      config: ["auth", "database"],
      connectors: ["database"],
    },
    action: async () => {
      await authService.cleanupExpiredTokens();

      const stale = await User.where("last_seen_at", "<", thirtyDaysAgo).get();

      for (const user of stale) {
        await authService.revokeAllTokens(user);
      }
    },
  });
}
```

Register it the same way as the bundled commands — call the factory inside `defineConfig({ cli: { commands: [...] } })`.

## Things NOT to do

- Don't run `jwt.generate` repeatedly in production. It changes the secret, which invalidates every token in flight. Generate once per environment.
- Don't run `auth.cleanup` from a long-running scheduler at sub-minute intervals. The DELETE itself is cheap, but the per-token `token.expired` event fan-out has cost. Hourly is plenty even at scale.
- Don't put the JWT secret in your codebase fallback (`env("JWT_SECRET", "dev-secret")`). A missing secret should fail the boot — not silently degrade to a dev value.

## See also

- [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md) — `cleanupExpiredTokens` internals
- [`@warlock.js/scheduler/scheduler-basics/SKILL.md`](@warlock.js/scheduler/scheduler-basics/SKILL.md) — in-process scheduling
