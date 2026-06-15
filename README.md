# Warlock Auth

JWT authentication for [Warlock.js](https://github.com/warlockjs/core) applications — a base `Auth` model your user types extend, an `authMiddleware` route gate, an `authService` for login / logout / refresh (with refresh-token rotation + replay detection), persisted access + refresh tokens, multi-user-type support, lifecycle events, brute-force throttling, and two CLI commands.

## Installation

```bash
yarn add @warlock.js/auth
```

`@warlock.js/auth` is coupled to `@warlock.js/core` — install it inside a Warlock project.

## Configure

```ts title="src/config/auth.ts"
import { type AuthConfigurations } from "@warlock.js/auth";
import { env } from "@warlock.js/core";
import { User } from "app/users/models/user";

const authConfigurations: AuthConfigurations = {
  userType: { user: User },
  accessToken: {
    secret: env("JWT_SECRET"),
    expiresIn: "1h",
  },
  refreshToken: {
    secret: env("JWT_REFRESH_SECRET"),
    expiresIn: "30d",
    rotation: true,
  },
};

export default authConfigurations;
```

The legacy `jwt: { secret, expiresIn, refresh: {…} }` block is still honored (with a deprecation warning), but prefer the `accessToken` / `refreshToken` blocks.

## Documentation

Task-focused guides live under [`skills/`](./skills):

- **overview** — what the package does and when to reach for it
- **auth-basics** — the `Auth` model, middleware, and service
- **handle-login-and-logout** — issue and revoke tokens
- **register-user** — sign up + first token pair
- **protect-routes** — gate routes with `authMiddleware`
- **manage-tokens** — the full token lifecycle (rotation, revocation, cleanup)
- **customize-user-type** — multiple user types in one system
- **customize-token-storage** — override the token models (multi-tenant columns, custom storage)
- **throttle-login-attempts** — brute-force protection via `loginThrottleMiddleware`
- **run-auth-commands** — the bundled CLI commands

## Generate the JWT secret

Register the command in `warlock.config.ts`:

```ts
import { registerJWTSecretGeneratorCommand } from "@warlock.js/auth";
import { defineConfig } from "@warlock.js/core";

export default defineConfig({
  cli: {
    commands: [registerJWTSecretGeneratorCommand()],
  },
});
```

Then run:

```bash
warlock jwt.generate
```

It generates cryptographically-strong `JWT_SECRET` and `JWT_REFRESH_SECRET` values and writes them to your `.env` file. Existing values are left untouched, so it's safe to re-run.

## License

MIT © Hasan Zohdy
