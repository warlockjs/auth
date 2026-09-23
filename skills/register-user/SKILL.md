---
name: register-user
description: "Register-and-issue-tokens flow in @warlock.js/auth; use when you need to register user."
---

# Register-and-issue-tokens flow

Two-step on the server: create the user (with hashed password), then issue tokens. Cascade handles the persistence; `authService` handles the tokens.

```ts title="src/app/users/models/user/user.model.ts"
import { Auth } from "@warlock.js/auth";
import { RegisterModel } from "@warlock.js/cascade";

@RegisterModel()
export class User extends Auth {
  public static table = "users";

  public get userType(): string {
    return "user";
  }
}
```

## The minimal shape

```ts
import { authService } from "@warlock.js/auth";
import { hashPassword, type RequestHandler } from "@warlock.js/core";
import { User } from "app/users/models/user/user.model";

export const registerController: RequestHandler = async ({ request, response }) => {
  const { email, password, name } = request.all();

  // 1. Check duplicates
  const existing = await User.first({ email });
  if (existing) {
    return response.conflict({ error: "Email already registered" });
  }

  // 2. Create the user with hashed password
  const user = await User.create({
    email,
    name,
    password: await hashPassword(password),
  });

  // 3. Issue tokens
  const tokens = await authService.createTokenPair(user, {
    userAgent: request.header("user-agent"),
    ip: request.ip,
  });

  // 4. Respond
  return response.successCreate({
    user,         // shape via static toJsonColumns / static resource
    tokens,
  });
};
```

That's the whole flow. `User.create({...})` runs the schema validation (including `.email()`, `.min()`, etc. on each field), so you don't need a separate validation pass — see [`@warlock.js/seal/handle-seal-errors/SKILL.md`](@warlock.js/seal/handle-seal-errors/SKILL.md) for catching validation failures.

## Hash the password on the way in

Always pass `hashPassword(plain)` — never store the plain password. The `hashPassword` helper is `bcrypt`-based and async; the cost factor matches the framework default.

```ts
import { hashPassword, verifyPassword } from "@warlock.js/core";

const hash = await hashPassword("plaintext");      // store this
const ok = await verifyPassword("plaintext", hash); // compare on login
```

`authService.attemptLogin` already calls `verifyPassword` against the stored hash — you don't compare passwords manually.

## Schema enforcement

Define the password as `v.string().strongPassword(12)` (or similar) in your User schema so weak passwords are rejected at `create()` time:

```ts
const userSchema = v.object({
  email: v.string().email(),
  name: v.string().min(2).max(120),
  password: v.string().strongPassword(12),   // 12+ chars, upper/lower/digit/symbol
  // status, role, etc.
});
```

But **don't return the password in the public output**:

```ts
@RegisterModel()
export class User extends Model<UserSchema> {
  public static table = "users";
  public static schema = userSchema;
  public static toJsonColumns = ["id", "email", "name", "created_at"];   // omit password
}
```

Without this, `JSON.stringify(user)` in your response leaks the hash.

## Email verification flow (extending registration)

Since 5.13 auth ships this. Declare `emailVerifiedAt: v.date().optional()` on the schema, then send the verification after creating the user:

```ts
import { authService, sendEmailVerification } from "@warlock.js/auth";

const user = await User.create({ ...data, password: await hashPassword(data.password) });

await sendEmailVerification(user); // hashed, single-use, 24h token via @warlock.js/notifications

const tokens = await authService.createTokenPair(user);
return response.successCreate({ user, tokens });
```

Gate routes that need a confirmed address with `requireVerifiedEmail()` after `authMiddleware`. See [`@warlock.js/auth/verify-email-and-reset-password/SKILL.md`](@warlock.js/auth/verify-email-and-reset-password/SKILL.md).

## Side effects via auth events

Hook post-registration logic:

```ts
import { authEvents } from "@warlock.js/auth";

authEvents.on("session.created", async (user, refreshToken, deviceInfo) => {
  if (user.get("created_at") > new Date(Date.now() - 5000)) {
    // freshly created in the last 5s — treat as registration
    await sendWelcomeEmail(user);
  }
});
```

Cleaner alternative: emit your own `user.registered` event from the controller after `User.create`. Decouples auth-package events from your domain events.

## Things NOT to do

- Don't pass the plain password to `User.create()`. `await hashPassword(plain)` first.
- Don't return the user without `toJsonColumns` / `resource` shaping — the password hash will leak otherwise.
- Don't issue tokens before validating the user shape. `User.create` runs validation; let it throw on bad input before tokens get created.
- Don't run "send welcome email" inline in the controller. Push it to a queue or run it after-commit via the outbox pattern — see [`@warlock.js/cascade/manage-transactions/SKILL.md`](@warlock.js/cascade/manage-transactions/SKILL.md).

## See also

- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — login flow (same `createTokenPair` step)
- [`@warlock.js/auth/manage-tokens/SKILL.md`](@warlock.js/auth/manage-tokens/SKILL.md) — token issuance internals
- [`@warlock.js/cascade/define-model/SKILL.md`](@warlock.js/cascade/define-model/SKILL.md) — `toJsonColumns` / `resource` for public output
