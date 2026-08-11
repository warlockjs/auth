---
name: protect-routes
description: 'Gate HTTP routes via authMiddleware(allowedUserType) — the argument is required and a valid token is always required: [] allows any authenticated user, a user-type restricts to those types. Sets request.user + request.decodedAccessToken on success, 401 on failure. Triggers: `authMiddleware`, `request.user`, `request.decodedAccessToken`, `AuthErrorCodes`, `MissingAccessToken`, `InvalidAccessToken`; "how do I protect a route", "restrict route by user type", "require any logged-in user"; typical import `import { authMiddleware } from "@warlock.js/auth"`. Skip: multi-user-type config — `@warlock.js/auth/customize-user-type/SKILL.md`; issuing the token — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; competing libs `passport`, `express-jwt`, `next-auth` middleware.'
---

# Gate routes with `authMiddleware`

`authMiddleware(allowedUserType: string | string[])` returns a Warlock middleware. Attach it to routes or route groups. The argument is **required** — there is no anonymous/optional mode. A request without a valid access token is always rejected with `401`; public routes simply omit the middleware.

## Two modes

Middleware is attached via the route's `options.middleware` array (the third argument) — never as a positional argument.

```ts
import { authMiddleware } from "@warlock.js/auth";

// Mode 1 — required, any user type
//   Rejects with 401 if no valid token; any authenticated user passes.
router.get("/account", accountController, {
  middleware: [authMiddleware([])],   // empty array = "any logged-in user"
});

// Mode 2 — required, specific user type(s)
//   Rejects with 401 if no token OR if token's userType isn't allowed.
router.get("/admin", adminController, {
  middleware: [authMiddleware("admin")],
});

router.get("/staff", staffController, {
  middleware: [authMiddleware(["admin", "staff"])],
});
```

The `userType` slug must match a key in `config.auth.userType.<name>` — see [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md).

## What the middleware does

On success, before your controller runs:

```ts
request.user = <hydrated user model instance>;
request.decodedAccessToken = <decoded JWT payload>;
```

The user is loaded via `Model.find(decodedToken.id)` against the `config.auth.userType[userType]` class. If the user no longer exists (deleted), the access token row is destroyed and the request gets 401.

A token passes three separate checks, in order — a token can fail any one of them while satisfying the other two:

1. **The JWT verifies** — signature, algorithm, `tokenType`, and (since 4.12.0) the presence of an `exp` claim that has not passed. A token with *no* `exp` is rejected: there is no deadline to check, so it would otherwise verify indefinitely.
2. **The access-token row still exists** — deleting it (logout) invalidates the token immediately, before its JWT expiry.
3. **The row's own `expires_at` has not passed** (since 4.12.0). The database is the authority on the session: a row whose expiry has elapsed is rejected and deleted, even if the JWT itself is still within its lifetime. A row with a missing or unparseable `expires_at` is treated as expired, not as never-expiring.

On failure, the middleware returns one of these 401 responses:

| Error code | When |
| --- | --- |
| `MissingAccessToken` | No `Authorization` header |
| `InvalidAccessToken` | Token doesn't verify (signature, missing/passed `exp`, wrong token type), has no DB row, or the row's `expires_at` has passed |
| `Unauthorized` | Token valid but user-type isn't in the allowed list |

## Reading the user in a controller

```ts
async function accountController(request: Request, response: Response) {
  const user = request.user!;          // typed via your Auth subclass
  return response.success({
    id: user.id,
    email: user.get("email"),
  });
}
```

Because the middleware always requires a valid token, `request.user` is guaranteed present inside any gated controller (the middleware would have responded 401 otherwise). The `!` is safe here.

## Route-group protection

```ts
router.group({ prefix: "/admin", middleware: [authMiddleware("admin")] }, () => {
  router.get("/users", listUsersController);
  router.post("/users", createUserController);
});
```

Every route inside the group is gated — the group's `middleware` array applies to each route in the callback. Cleaner than repeating the middleware on each route.

## No optional / fallthrough auth

There is no "hydrate `request.user` if a token is present, otherwise continue" mode. `authMiddleware` always requires a valid token. If a route should be reachable anonymously, leave the middleware off — and read the token yourself in the controller if you want soft personalization:

```ts
async function feedController(request: Request, response: Response) {
  const token = request.authorizationValue;
  // optionally decode/hydrate manually when a token is present
}
```

## Custom error responses

The middleware uses the framework's `response.unauthorized({...})` shape. To override the response globally, hook the framework's error transformer to remap `AuthErrorCodes.*` codes.

## When flat user types aren't enough — reach for `@warlock.js/access`

`authMiddleware` gates on **user type** by flat string membership. That answers "is this an admin?" and nothing more. It deliberately cannot express:

- a permission matrix (`articles.publish` rather than `"editor"`)
- role hierarchy or inheritance
- **who may act on whom** — "an `admin` may create a `teacher`, but only a `superAdmin` may create or promote an `admin`"

That last one is the difference between a role check and an authorization model: without it, an account-creation endpoint gated on `authMiddleware("admin")` is a privilege-escalation path.

Install [`@warlock.js/access`](@warlock.js/access/overview/SKILL.md) for that. It layers RBAC plus per-permission ABAC policies over the same authenticated user:

```ts
import { gate, can, definePolicy } from "@warlock.js/access";

// Permission-based route gate, in place of a user-type gate
router.post("/articles", articlesController, { middleware: [authMiddleware([]), gate("articles.create")] });

// Who-may-act-on-whom: an ABAC policy on top of the RBAC grant
definePolicy("users.create", (actor, target, ctx) =>
  ctx.hasRole("superAdmin") || (target as User).userType === "teacher",
);

if (await can(request.user, "users.create", { resource: payload })) { /* ... */ }
```

Use `authMiddleware` to establish *who the caller is*, and `access` to decide *what they may do*. They compose — `access` reads the user `authMiddleware` put on the request.

## Sessions are bearer-token, not cookie

The token is read from the `Authorization` header (`Bearer <token>` or `Key <token>`) and nowhere else. "Session" in this package means a **refresh-token row**, not an HTTP cookie session.

There is no cookie-backed guard, no session store, and no cookie strategy in `authMiddleware` — that is the intended design, not an omission. Warlock's auth optimises for API services.

If you want HttpOnly cookie sessions for a server-rendered admin, that is **app-level work**: set the cookie yourself with `response.cookie` (secure by default since 4.10.0) and read it in your own middleware, then hand the token to the same `authService` rotation logic. **You also own CSRF** — the framework ships no CSRF helper, and cookie auth needs one where bearer auth does not. A synchronizer token bound to the session plus `Origin`/`Referer` checks is the usual shape.

## Things NOT to do

- Don't call `authMiddleware` outside route definition. It returns a function — the function is what runs per-request. Calling it once per request creates a fresh middleware on every hit (wasteful) and a fresh allowed-types Set (correctness if the input changes per call).
- Don't manually decode JWTs in the controller. The middleware already does it and exposes the decoded payload via `request.decodedAccessToken`.
- Don't trust `request.user` set by client-supplied headers. The middleware is the only place that sets it on the server — client headers can't reach this slot.
- Don't pass an unknown user-type to `authMiddleware("typo")`. The middleware will reject every request because the lookup fails. Test the wire-up with a real token of each user type.

## See also

- [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md) — config and multi-user-type semantics
- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — where the access token gets issued in the first place
- [`@warlock.js/auth/throttle-login-attempts/SKILL.md`](@warlock.js/auth/throttle-login-attempts/SKILL.md) — brute-force throttle to stack in front of the login route
- [`@warlock.js/access/overview/SKILL.md`](@warlock.js/access/overview/SKILL.md) — permissions, roles, and who-may-act-on-whom policies, when user-type gating isn't enough
