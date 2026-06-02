---
name: register-user
description: 'Sign up a new user and issue the initial token pair — User.create({...password: await hashPassword(plain)}) then authService.createTokenPair(user). Triggers: `User.create`, `hashPassword`, `verifyPassword`, `authService.createTokenPair`, `toJsonColumns`, `strongPassword`, `authEvents`; "build a register endpoint", "POST /register controller", "sign up a new user", "hash password on signup", "email verification flow"; typical import `import { authService } from "@warlock.js/auth"; import { hashPassword } from "@warlock.js/core"`. Skip: login — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; token internals — `@warlock.js/auth/manage-tokens/SKILL.md`; competing libs `bcrypt`, `bcryptjs`, `argon2`.'
---

# Register-and-issue-tokens flow

Two-step on the server: create the user (with hashed password), then issue tokens. Cascade handles the persistence; `authService` handles the tokens.

## The minimal shape

```ts
import { authService } from "@warlock.js/auth";
import { hashPassword } from "@warlock.js/core";
import { User } from "@/app/users/models/user.model";

async function registerController(request: Request, response: Response) {
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
}
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

Common pattern: create the user as `email_verified = false`, send a verification email, mark verified on click. The auth package doesn't ship this; build it on top:

```ts
const user = await User.create({
  ...data,
  email_verified: false,
  verification_token: Random.string(64),
});

await mailer.sendVerificationEmail(user.get("email"), user.get("verification_token"));

const tokens = await authService.createTokenPair(user);
return response.successCreate({ user, tokens });
```

Optional: pre-verification, restrict the user to a `unverified` user-type and gate routes accordingly via `authMiddleware("user")`. After verification, swap user-type to `user`.

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
