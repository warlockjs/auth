---
name: protect-routes
description: 'Gate HTTP routes via authMiddleware(allowedUserType) — the argument is required and a valid token is always required: [] allows any authenticated user, a user-type restricts to those types. Sets request.locals.user + request.decodedAccessToken on success, 401 on failure. Triggers: `authMiddleware`, `request.locals.user`, `request.decodedAccessToken`, `AuthErrorCodes`, `MissingAccessToken`, `InvalidAccessToken`; "how do I protect a route", "restrict route by user type", "require any logged-in user"; typical import `import { authMiddleware } from "@warlock.js/auth"`. Skip: multi-user-type config — `@warlock.js/auth/customize-user-type/SKILL.md`; issuing the token — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; competing libs `passport`, `express-jwt`, `next-auth` middleware.'
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
request.locals.user = <hydrated user model instance>;
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

## Page routes: redirect to login instead of the JSON 401

By default every auth failure — API or page — returns the JSON `401` above. That's right for an API client, but a logged-out human who *navigates* to a guarded page route gets a raw JSON error blob instead of a login screen.

Opt into a redirect with `auth.pageAuth` (5.8+). Set `loginPath` and a guarded **page** route (`route.isPage`) that a logged-out browser hits redirects to `loginPath?returnUrl=<original path>` instead of returning the JSON 401:

```ts title="src/config/auth.ts"
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

> `auth.pageAuth` is **not a second auth mechanism** — it is a convenience *adapter* over the same "not authenticated" outcome the gate already produces. It only changes the **representation** of that outcome on a page route (a browser-friendly login redirect) instead of the JSON `401`; the decision that the request is unauthenticated is unchanged. The sanctioned *generic* way to make authentication soft is the app-owned optional-auth middleware below — `pageAuth` is the built-in adapter for the common "redirect a logged-out human to /login" case, so most apps never need to hand-roll it.

## Reading the user in a controller

```ts
import { type RequestHandler } from "@warlock.js/core";

export const accountController: RequestHandler = async ({ request, response }) => {
  const user = request.locals.user!;          // typed via your Auth subclass
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

## Optional auth is an app-owned middleware (the sanctioned pattern)

`authMiddleware` is a **hard gate** — it always requires a valid token and rejects when one is absent. There is deliberately no built-in "hydrate `request.locals.user` if a token is present, otherwise continue" mode, because the *sanctioned generic pattern* for soft/optional auth is a small **app-owned optional-auth middleware**: resolve the user when a valid token is present, and otherwise leave the route to decide. The app owns it because the "what to do when absent" policy is the app's, not the framework's.

```ts title="src/app/middleware/optional-auth.middleware.ts"
import { type Middleware } from "@warlock.js/core";
import { jwt } from "@warlock.js/auth";

// The one sanctioned optional-auth shape: resolve if present, never reject.
// Middleware receives the context object ({ request, response }), like a handler.
export const optionalAuth: Middleware = async ({ request }) => {
  const token = request.authorizationValue;
  if (!token) return; // absent → continue anonymously; the route decides
  try {
    const decoded = await jwt.verify(token);
    // hydrate request.locals.user from your token/user model when valid
  } catch {
    // invalid token on an optional route → treat as anonymous, don't reject
  }
  // returning nothing (undefined) === continue to the handler
};
```

Wire it like any middleware (`{ middleware: [optionalAuth] }`), then branch on `request.locals.user` in the controller. Use `authMiddleware` when the route must be gated; use this when the route is public but personalizes for a signed-in user. `auth.pageAuth` (above) is the built-in **adapter** over this same "unauthenticated" outcome for the common page-redirect case — it is not a competing mechanism.

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

if (await can(request.locals.user, "users.create", { resource: payload })) { /* ... */ }
```

Use `authMiddleware` to establish *who the caller is*, and `access` to decide *what they may do*. They compose — `access` reads the user `authMiddleware` put on the request.

## Cookie sessions: `authMiddleware([], "cookie:<name>")`

`authMiddleware`'s second argument, `tokenFrom`, selects the credential source and defaults to `"header"`. Pass `` `cookie:<name>` `` to read the credential from a named cookie instead of the `Authorization` header — the same gate, the same three checks, the same `request.locals.user` / `request.decodedAccessToken` outcome, just a different place to find the token:

```ts
router.get("/browser-account", accountController, {
  middleware: [authMiddleware([], "cookie:token")],
});
```

A route is header-only or cookie-only, never both — `tokenFrom` accepts exactly one source, so there is no header/cookie precedence to define. A route that legitimately needs to accept either composes two `authMiddleware` instances against the app's own optional-auth pattern (above).

### Writing and clearing the cookie: `authService.setAuthCookie` / `clearAuthCookie`

Reading a cookie is opt-in per route (above); *writing* one is a separate, explicit step your login/logout controller calls — `authService.login`/`logout` never set cookies implicitly, so upgrading never starts emitting `Set-Cookie` for an existing bearer-only app.

```ts
import { authService } from "@warlock.js/auth";

// after issuing tokens
const { user, tokens } = await authService.login(User, credentials);
authService.setAuthCookie(response, tokens.accessToken); // Max-Age derived from tokens.accessToken.expiresAt

// after revoking tokens
await authService.logout(user, accessToken, refreshToken);
authService.clearAuthCookie(response);
```

`setAuthCookie(response, token, options?)` accepts either the raw token string or an `AccessTokenOutput` (`{ token, expiresAt }`, e.g. `tokens.accessToken` from `login`) — passing the latter derives `Max-Age` from `expiresAt` automatically; pass `options.maxAge` (seconds) to override it, or a bare string with no `maxAge` for a session cookie. `clearAuthCookie(response, options?)` clears it.

Cookie **attribute flags are not configurable** — `HttpOnly`, `SameSite=Lax`, and `Secure` outside development come from core's `secureCookieDefaults()`, the same floor every `response.cookie()` call gets. Only the cookie's `name` (default `"access_token"`) and `path` (default `"/"`) can be set, via `options` or the `auth.cookie` config block:

```ts title="src/config/auth.ts"
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
