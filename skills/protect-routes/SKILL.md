---
name: protect-routes
description: 'Gate HTTP routes via authMiddleware(allowedUserType) — the argument is required and a valid token is always required: [] allows any authenticated user, a user-type restricts to those types. Sets request.locals.user + request.decodedAccessToken on success, 401 on failure. Triggers: `authMiddleware`, `request.locals.user`, `request.decodedAccessToken`, `AuthErrorCodes`, `MissingAccessToken`, `InvalidAccessToken`; "how do I protect a route", "restrict route by user type", "require any logged-in user"; typical import `import { authMiddleware } from "@warlock.js/auth"`. Skip: multi-user-type config — `@warlock.js/auth/customize-user-type/SKILL.md`; issuing the token — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; competing libs `passport`, `express-jwt`, `next-auth` middleware.'
---

# Gate routes with `authMiddleware`

`authMiddleware` returns a Warlock middleware. Attach it to routes or route groups. The legacy string overload is preserved; the object overload makes credential source, optional resolution, and a page-local redirect explicit.

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

## Two modes

Middleware is attached via the route's `options.middleware` array (the third argument) — never as a positional argument.

```ts
import { router, type RequestHandler } from "@warlock.js/core";
import { authMiddleware } from "@warlock.js/auth";

const accountController: RequestHandler = async ({ response }) => response.success({});
const adminController: RequestHandler = async ({ response }) => response.success({});
const staffController: RequestHandler = async ({ response }) => response.success({});

// Required default type (`auth.defaultUserType`, or the sole configured type)
router.get("/account", accountController, {
  middleware: [authMiddleware()],
});

// Mode 2 — required, specific user type(s)
//   Rejects missing/invalid credentials with 401 and a disallowed user type with 403.
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
request.locals.user = <hydrated user model instance>;
request.decodedAccessToken = <decoded JWT payload>;
```

The user is loaded via `Model.find(decodedToken.id)` against the `config.auth.userType[userType]` class. If the user no longer exists (deleted), the access token row is destroyed and the request gets 401.

A token passes three separate checks, in order — a token can fail any one of them while satisfying the other two:

1. **The JWT verifies** — signature, algorithm, `tokenType`, and (since 4.12.0) the presence of an `exp` claim that has not passed. A token with *no* `exp` is rejected: there is no deadline to check, so it would otherwise verify indefinitely.
2. **The access-token row still exists** — deleting it (logout) invalidates the token immediately, before its JWT expiry.
3. **The row's own `expires_at` has not passed** (since 4.12.0). The database is the authority on the session: a row whose expiry has elapsed is rejected and deleted, even if the JWT itself is still within its lifetime. A row with a missing or unparseable `expires_at` is treated as expired, not as never-expiring.

Missing or invalid credentials return 401; an authenticated disallowed user type returns 403:

| Error code | When |
| --- | --- |
| `MissingAccessToken` | No credential at the configured source |
| `InvalidAccessToken` | Token doesn't verify (signature, missing/passed `exp`, wrong token type), has no DB row, or the row's `expires_at` has passed |
| `Unauthorized` | Token valid but user-type isn't in the allowed list (403) |

## Page routes: redirect to login instead of the JSON 401

By default every auth failure — API or page — returns the JSON `401` above. That's right for an API client, but a logged-out human who *navigates* to a guarded page route gets a raw JSON error blob instead of a login screen.

Opt into a redirect with `auth.pageAuth` (5.8+). Set `loginPath` and a guarded **page** route (`route.isPage`) that a logged-out browser hits redirects to `loginPath?returnUrl=<original path>` instead of returning the JSON 401:

```ts title="src/config/auth.ts"
import { User } from "app/users/models/user/user.model";

export default {
  userType: { user: User },
  pageAuth: {
    loginPath: "/login",        // set this to turn the redirect on
    returnUrlParam: "returnUrl", // optional, this is the default
  },
};
```

Behavior, precisely:

- **Page route + `loginPath` set** → `302` redirect to `loginPath?returnUrl=<encoded request path>`. The login flow reads `returnUrl` to send the user back where they were headed. If `loginPath` already carries a query string, the param is appended with `&` instead of `?`.
- **Page route + `loginPath` unset** → the JSON `401` is unchanged. The redirect is **opt-in**, so an app that hasn't configured `pageAuth` keeps exactly its current behavior.
- **API route** → always the JSON `401`, regardless of `pageAuth`. The API contract is never altered.

The page-vs-API signal is `request.route.isPage`. Config is typed as `PageAuthConfig` on `AuthConfigurations` (`loginPath?: string`, `returnUrlParam?: string`, default `"returnUrl"`); read at runtime through `authConfig.pageAuth`.

> A local `redirect` object is preferred for a page that needs a different login destination; absent it, `auth.pageAuth` remains the compatibility fallback.

## Reading the user in a controller

`request.locals.user` types as `RequestUser` — an empty interface by default. Narrow it once, app-wide, via module augmentation so it carries your model's shape:

```ts title="src/app/users/request-user.ts"
import type { User } from "app/users/models/user/user.model";

declare module "@warlock.js/auth" {
  interface RequestUser extends User {}
}
```

```ts
import { type RequestHandler } from "@warlock.js/core";

export const accountController: RequestHandler = async ({ request, response }) => {
  const user = request.locals.user!;          // typed via the RequestUser augmentation above
  return response.success({
    id: user.id,
    email: user.get("email"),
  });
};
```

Because the middleware always requires a valid token, `request.locals.user` is guaranteed present inside any gated controller (the middleware would have responded 401 otherwise). The `!` is safe here.

## Route-group protection

```ts
router.group({ prefix: "/admin", middleware: [authMiddleware("admin")] }, () => {
  router.get("/users", listUsersController);
  router.post("/users", createUserController);
});
```

Every route inside the group is gated — the group's `middleware` array applies to each route in the callback. Cleaner than repeating the middleware on each route.

## Optional auth

Use `optional: true` in the object form when a public route should receive a verified user when one is present. Missing or invalid credentials continue anonymously; a hard gate remains the default.

```ts
middleware: [authMiddleware({ source: "header", optional: true })]
```

## Automatic cookie renewal

Add `refresh: { source: "cookie", key: "refresh_token", overlapMs?: 5000 }`
to a typed cookie middleware to renew an absent, invalid, or expired access
cookie before the handler. It writes the successor access and refresh cookies
through `authService.setAuthCookie`; it never replays a handler. `overlapMs` is
clamped to 0â€“10,000 ms (default 5,000). Only the exact immediate successor is
tolerated during that window. The legacy `refreshTokens` API stays strict; a
later old-token presentation revokes its family.
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
import { router, type RequestHandler } from "@warlock.js/core";
import { authMiddleware } from "@warlock.js/auth";
import { gate, can, definePolicy } from "@warlock.js/access";
import { User } from "app/users/models/user/user.model";

const articlesController: RequestHandler = async ({ request, response }) => {
  // Who-may-act-on-whom: an ABAC policy on top of the RBAC grant
  definePolicy("users.create", (actor, target, ctx) =>
    ctx.hasRole("superAdmin") || (target as User).userType === "teacher",
  );

  if (await can(request.locals.user!, "users.create", { resource: request.body })) {
    /* ... */
  }

  return response.success({});
};

// Permission-based route gate, in place of a user-type gate
router.post("/articles", articlesController, { middleware: [authMiddleware([]), gate("articles.create")] });
```

Use `authMiddleware` to establish *who the caller is*, and `access` to decide *what they may do*. They compose — `access` reads the user `authMiddleware` put on the request.

## Cookie credentials

Use `{ source: "cookie", key: "token" }` in the object form. The same checks and `request.locals.user` outcome apply; legacy `authMiddleware("user", "cookie:token")` is also supported.

```ts
router.get("/browser-account", accountController, {
  middleware: [authMiddleware({ source: "cookie", key: "token" })],
});
```

A route is header-only or cookie-only, never both — `tokenFrom` accepts exactly one source, so there is no header/cookie precedence to define. A route that legitimately needs to accept either composes two `authMiddleware` instances against the app's own optional-auth pattern (above).

### Writing and clearing the cookie: `authService.setAuthCookie` / `clearAuthCookie`

Reading a cookie is opt-in per route (above); *writing* one is a separate, explicit step your login/logout controller calls — `authService.login`/`logout` never set cookies implicitly, so upgrading never starts emitting `Set-Cookie` for an existing bearer-only app.

```ts
import { type RequestHandler } from "@warlock.js/core";
import { authService } from "@warlock.js/auth";
import { User } from "app/users/models/user/user.model";

export const loginController: RequestHandler = async ({ request, response }) => {
  const result = await authService.login(User, {
    email: request.input("email"),
    password: request.input("password"),
  });
  if (!result) return response.unauthorized({ error: "Invalid credentials" });

  const { user, tokens } = result;
  authService.setAuthCookie(response, tokens.accessToken); // Max-Age derived from tokens.accessToken.expiresAt

  return response.success({ id: user.id });
};

export const logoutController: RequestHandler = async ({ request, response }) => {
  const user = request.locals.user!;
  await authService.logout(user, request.header("authorization"));
  authService.clearAuthCookie(response);

  return response.success({});
};
```

`setAuthCookie(response, token, options?)` accepts either the raw token string or an `AccessTokenOutput` (`{ token, expiresAt }`, e.g. `tokens.accessToken` from `login`) — passing the latter derives `Max-Age` from `expiresAt` automatically; pass `options.maxAge` (seconds) to override it, or a bare string with no `maxAge` for a session cookie. `clearAuthCookie(response, options?)` clears it.

Cookie **attribute flags are not configurable** — `HttpOnly`, `SameSite=Lax`, and `Secure` outside development come from core's `secureCookieDefaults()`, the same floor every `response.cookie()` call gets. Only the cookie's `name` (default `"access_token"`) and `path` (default `"/"`) can be set, via `options` or the `auth.cookie` config block:

```ts title="src/config/auth.ts"
import { User } from "app/users/models/user/user.model";

export default {
  userType: { user: User },
  cookie: {
    name: "access_token", // must match the `cookie:<name>` a route reads
    path: "/",
  },
};
```

The cookie name `setAuthCookie`/`clearAuthCookie` write **must match** the name a `cookie:<name>` token source reads — they are not linked automatically.

### CSRF: an automatic Origin check on cookie-authenticated writes

Cookie auth changes the CSRF picture that bearer-token auth doesn't have: a browser attaches cookies to same-site requests it didn't originate. `SameSite=Lax` already blocks the classic cross-site `<form method="post">` case, but not a same-site GET redirect chain or a client that ignores `SameSite`.

To close that gap, `authMiddleware` automatically runs a CSRF Origin check on every request whose credential came from a `cookie:` source **and** whose method is unsafe (`POST`/`PUT`/`PATCH`/`DELETE`) — there is nothing to opt into, and nothing to configure to turn it on:

- **Allowed** when `Origin` equals the request's own origin, or is listed in `auth.csrf.allowedOrigins` (config, default `[]`).
- If `Origin` is absent, `Referer`'s origin is checked the same way.
- If **both** are absent, or the check fails, the request is rejected with `403` and `errorCode: AuthErrorCodes.CsrfOriginMismatch` ("EC006") — never silently passed through.
- **Header-token auth is completely unaffected**, as are safe methods (`GET`/`HEAD`/`OPTIONS`) under cookie auth.

```ts title="src/config/auth.ts"
import { User } from "app/users/models/user/user.model";

export default {
  userType: { user: User },
  csrf: {
    allowedOrigins: ["https://admin.example.com"], // extra trusted origins, beyond same-origin
  },
};
```

This is an Origin check, not a double-submit CSRF token — cheaper, and closes the gap `SameSite=Lax` leaves open, but it doesn't help a client whose privacy proxy strips both `Origin` and `Referer` (that request is rejected outright, fail-closed, rather than silently allowed). A double-submit token mechanism is deferred to a later release; track it if your threat model includes Origin-stripping clients.

## Things NOT to do

- Don't call `authMiddleware` outside route definition. It returns a function — the function is what runs per-request. Calling it once per request creates a fresh middleware on every hit (wasteful) and a fresh allowed-types Set (correctness if the input changes per call).
- Don't manually decode JWTs in the controller. The middleware already does it and exposes the decoded payload via `request.decodedAccessToken`.
- Don't trust `request.locals.user` set by client-supplied headers. The middleware is the only place that sets it on the server — client headers can't reach this slot.
- Don't pass an unknown user-type to `authMiddleware("typo")`. The middleware will reject every request because the lookup fails. Test the wire-up with a real token of each user type.

## See also

- [`@warlock.js/auth/customize-user-type/SKILL.md`](@warlock.js/auth/customize-user-type/SKILL.md) — config and multi-user-type semantics
- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md) — where the access token gets issued in the first place
- [`@warlock.js/auth/throttle-login-attempts/SKILL.md`](@warlock.js/auth/throttle-login-attempts/SKILL.md) — brute-force throttle to stack in front of the login route
- [`@warlock.js/access/overview/SKILL.md`](@warlock.js/access/overview/SKILL.md) — permissions, roles, and who-may-act-on-whom policies, when user-type gating isn't enough
