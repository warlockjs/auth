---
name: customize-user-type
description: 'Support multiple user types (user / admin / client / staff) in one auth system — each Auth subclass overrides userType, config.auth.userType.<slug> maps slug to model class, authMiddleware(''admin'') gates per type. Triggers: `Auth`, `userType`, `config.auth.userType`, `Authenticable`, `@RegisterModel`, `confirmPassword`; "add admins and users", "multiple user types", "separate client and vendor personas", "per-type login"; typical import `import { Auth } from "@warlock.js/auth"`. Skip: `authMiddleware` semantics — `@warlock.js/auth/protect-routes/SKILL.md`; login flow — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; RBAC libs `casl`, `accesscontrol`, `rbac`.'
---

# Customize user type (multi-user-type auth)

The `Auth` base class has a `userType` slot. Subclass it once per type, register each class under `config.auth.userType.<slug>`, and the auth flow handles the rest.

## Define a model per user type

```ts title="src/app/users/models/user/user.model.ts"
import { Auth } from "@warlock.js/auth";
import { RegisterModel } from "@warlock.js/cascade";

@RegisterModel()
export class User extends Auth<UserSchema> {
  public static table = "users";
  public static schema = userSchema;

  public get userType(): string {
    return "user";
  }
}
```

```ts title="src/app/admins/models/admin/admin.model.ts"
@RegisterModel()
export class Admin extends Auth<AdminSchema> {
  public static table = "admins";
  public static schema = adminSchema;

  public get userType(): string {
    return "admin";
  }
}
```

Each gets its own table, its own schema, its own `userType` slug. They DON'T share table — they're separate models.

## Register them in `config.auth`

```ts title="src/config/auth.ts"
import { User } from "@/app/users/models/user.model";
import { Admin } from "@/app/admins/models/admin.model";

export default {
  userType: {
    user: User,
    admin: Admin,
    // staff: Staff,
    // client: Client,
  },
  jwt: {
    secret: env("JWT_SECRET"),
    expiresIn: "1h",
    refresh: { enabled: true, expiresIn: "30d", rotation: true },
  },
};
```

The keys (`"user"`, `"admin"`) are the **userType slugs** that flow through every token, middleware call, and event payload.

## Gate routes per user type

```ts
import { authMiddleware } from "@warlock.js/auth";

router.get("/account", userAccountController, { middleware: [authMiddleware("user")] });
router.get("/admin/users", listUsersController, { middleware: [authMiddleware("admin")] });
router.get("/back-office", backOfficeController, { middleware: [authMiddleware(["admin", "staff"])] });
router.get("/dashboard", dashboardController, { middleware: [authMiddleware([])] }); // any logged-in
```

See [`@warlock.js/auth/protect-routes/SKILL.md`](@warlock.js/auth/protect-routes/SKILL.md).

## Login per user type — pass the right Model

`authService.login(Model, credentials, deviceInfo?)` is keyed off the model you pass:

```ts
// User login endpoint
const result = await authService.login(User, credentials);
// Issues tokens with userType "user"; middleware will route them to User model.

// Admin login endpoint
const result = await authService.login(Admin, credentials);
// Issues tokens with userType "admin"; middleware will route them to Admin model.
```

The middleware then uses `config.auth.userType[token.userType]` to know which model to hydrate.

## Cross-type behavior

- **Tokens are scoped to their issuing user-type.** A user-type token doesn't unlock admin-type routes.
- **AccessToken / RefreshToken rows carry the `user_type` column.** Same model classes, different rows per type.
- **`authMiddleware(["admin", "user"])`** allows either — useful for endpoints shared between roles.

## When NOT to use multi-user-type

If the distinction is **permissions/roles within one user shape**, use a `role` column on a single User model instead. Multi-user-type is right when:

- Different tables / schemas (admins have an `admin_level`; users have a `subscription_tier`).
- Separate registration flows (admins are created via an admin panel; users self-register).
- Truly separate concepts at the data layer (clients vs vendors in a marketplace).

If users and admins differ only in a `role` field, stick with one `User` model + a role check at the controller layer.

## `Auth` base — what your subclass inherits

```ts
abstract class Auth<TSchema> extends Model<TSchema> implements Authenticable {
  // ...all the Model<> methods
  public abstract get userType(): string;
  public generateAccessToken(payload?: Record<string, unknown>): Promise<AccessTokenOutput>;
  public generateRefreshToken(deviceInfo?: DeviceInfo): Promise<RefreshToken | undefined>;
  public createTokenPair(deviceInfo?: DeviceInfo): Promise<TokenPair>;
  public confirmPassword(password: string): Promise<boolean>;
}
```

`userType` is the only required override (an abstract getter — return the type slug). Override `generateAccessToken` if you need a non-default payload.

`Auth` implements the `Authenticable` contract — that interface mirrors exactly these methods (`userType`, `generateAccessToken`, `generateRefreshToken`, `createTokenPair`, `confirmPassword`), so the class fails to compile if it drifts from the contract. Use `confirmPassword(plaintext)` to check a password against the stored hash (e.g. a "confirm current password" step).

## Things NOT to do

- Don't use multi-user-type for what's really role-based access control. Use a `role` column on a single User model when the data shape is shared.
- Don't forget the `public get userType(): string` override. It's an abstract getter on `Auth` — a subclass without it won't compile, and middleware lookups key off its return value.
- Don't reuse the same `userType` slug across two models — the `config.auth.userType` map can only point one slug at one model.
- Don't put admins and users in the same table differentiated by a flag. Separate tables means migrations don't coupling, queries don't accidentally cross, and audit logs are cleaner.

## See also

- [`@warlock.js/auth/protect-routes/SKILL.md`](@warlock.js/auth/protect-routes/SKILL.md) — `authMiddleware` semantics
- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — passing the right Model to `login`
- [`@warlock.js/cascade/define-model/SKILL.md`](@warlock.js/cascade/define-model/SKILL.md) — `@RegisterModel`, models in general
