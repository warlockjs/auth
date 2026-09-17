---
name: login-with-providers
description: 'Log in without a password — Google (OIDC code + PKCE + state + nonce, id_token verified with `jose`), passkeys (WebAuthn via `@simplewebauthn/server`) and phone one-time codes (delivered through a `@warlock.js/notifications` channel). Every method ends in `authService.completeLogin(user)`, the same tokens, rows and events as password login. `startProviderLogin`, `completeProviderLogin`, `generatePasskeyRegistrationOptions`, `verifyPasskeyRegistration`, `generatePasskeyAuthenticationOptions`, `verifyPasskeyAuthentication`, `requestOtp`, `verifyOtp`, `otpRequestThrottleMiddleware`, `otpVerifyThrottleMiddleware`, `AuthProvider`. Triggers: "login with Google", "sign in with Google", "OAuth", "OIDC", "passkeys", "WebAuthn", "passwordless", "SMS code login", "WhatsApp OTP", "phone login", `warlock add auth-google`, `warlock add auth-passkeys`, `AuthProviderSdkMissingError`, `InvalidProviderCallbackError`, `ProviderEmailNotVerifiedError`, `InvalidPasskeyError`, `EC009`, `EC010`, `EC011`, `auth.providers`, `auth.passkeys`, `auth.otp`; typical import `import { completeProviderLogin, verifyOtp } from "@warlock.js/auth"`. Skip: password login — `@warlock.js/auth/handle-login-and-logout/SKILL.md`; email tokens — `@warlock.js/auth/verify-email-and-reset-password/SKILL.md`; defining an SMS channel — `@warlock.js/notifications/define-channel/SKILL.md`.'
---

# Login with Google, passkeys, or a phone code

Services only, as with password login: you write the routes. Each `verify`/`complete` call returns the same `LoginResult` as `authService.login`, so the next step is the same too:

```ts
const { user, tokens } = await completeProviderLogin(User, "google", request, response);
authService.setAuthCookie(response, tokens.accessToken); // cookie session, or return tokens as JSON
```

`authService.completeLogin(user, deviceInfo?)` is that shared ending. It applies `auth.canAuthenticate` (403) and issues tokens. Call it only for a user you have already authenticated.

## Install

| Method | Command | Installs |
| --- | --- | --- |
| Google | `warlock add auth-google` | `jose` |
| Passkeys | `warlock add auth-passkeys` | `@simplewebauthn/server` (add `@simplewebauthn/browser` to your client bundle) |
| Phone code | `warlock add notifications` + your own `sms`/`whatsapp` channel | nothing else. Auth ships no SMS/WhatsApp driver |

The SDKs are optional peers, loaded with `import()` only when a method runs. If one is missing, the call throws `AuthProviderSdkMissingError` (500), and the message names the `warlock add` command. Run the migrations: `authMigrations` now includes `provider_accounts` and `passkey_credentials`, and `one_time_tokens` gained an `attempts` column.

## Google

```ts
// src/config/auth.ts
providers: {
  google: {
    clientId: env("GOOGLE_CLIENT_ID"),
    clientSecret: env("GOOGLE_CLIENT_SECRET"),
    redirectUri: `${env("APP_URL")}/auth/google/callback`, // exactly as registered at Google
    // scopes: ["openid", "email", "profile"],
  },
  // emailField: "email",
  // createUser: async (profile, Model) => Model.create({ ... }),
},
```

```ts
router.get("/auth/google", async ({ response }) =>
  response.redirect(await startProviderLogin(response, "google")),
);

router.get("/auth/google/callback", async ({ request, response }) => {
  const { tokens } = await completeProviderLogin(User, "google", request, response);
  authService.setAuthCookie(response, tokens.accessToken);
  return response.redirect("/");
});
```

Client side, the button is just a link. It must be a top-level navigation, not a `fetch`, so the state cookie goes out and comes back:

```tsx
<a href="/auth/google">Continue with Google</a>
```

- `state`, `nonce` and the PKCE verifier go into a signed, 10-minute, HttpOnly `auth_provider_state` cookie (SameSite=Lax, so it survives Google's redirect back). The callback clears the cookie, so a started login can complete only once.
- The callback rejects, with `InvalidProviderCallbackError` (400, `EC009`): a missing, forged or expired cookie, a `state` mismatch, a `?error=` from Google, a failed code exchange, and an id_token with a bad signature, `iss`, `aud`, `exp` or `nonce`. `error.reason` says which. The response message is generic.
- **Linking.** An existing `provider_accounts` row (provider plus Google `sub`) always decides the user. Without one, the Google email must be verified (`email_verified: true`), or the call throws `ProviderEmailNotVerifiedError` (403, `EC010`) and nothing is linked or created. A verified email links the matching user, or creates one with `{ email, name, emailVerifiedAt: now }`.
- Other OIDC providers: implement `AuthProvider` (`authorizationUrl(state)`, `handleCallback({ query, expected })`) and register it under `auth.providers.custom.<name>`.

## Passkeys

```ts
passkeys: { rpID: "example.com", rpName: "Example", origin: "https://example.com" },
```

```ts
// Register (logged in)
router.post("/auth/passkeys/register/options", async ({ request, response }) =>
  response.success(await generatePasskeyRegistrationOptions(request.locals.user)),
  { middleware: [authMiddleware("user")] });
router.post("/auth/passkeys/register", async ({ request, response }) => {
  await verifyPasskeyRegistration(request, request.locals.user, request.input("credential"));
  return response.success({ registered: true });
}, { middleware: [authMiddleware("user")] });

// Log in
router.post("/auth/passkeys/login/options", async ({ response }) =>
  response.success(await generatePasskeyAuthenticationOptions()));
router.post("/auth/passkeys/login", async ({ request, response }) => {
  const { tokens } = await verifyPasskeyAuthentication(request, request.input("credential"));
  authService.setAuthCookie(response, tokens.accessToken);
  return response.success({ ok: true });
});
```

Browser:

```ts
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";

const post = (url: string, body?: unknown) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json());

// register
const regOptions = await post("/auth/passkeys/register/options");
await post("/auth/passkeys/register", { credential: await startRegistration({ optionsJSON: regOptions }) });

// log in
const authOptions = await post("/auth/passkeys/login/options");
await post("/auth/passkeys/login", { credential: await startAuthentication({ optionsJSON: authOptions }) });
```

(Unwrap `response.success`'s envelope if your app wraps payloads.)

- Challenges live in `one_time_tokens` as SHA-256 hashes, expire after 5m (`auth.passkeys.challengeExpiresIn`), and are **consumed before verification**. A replayed challenge fails, and so does one whose first verification failed.
- The request `Origin` must be one of `auth.passkeys.origin`. The same list is checked against the signed `clientDataJSON`.
- The signature counter must advance. A counter that did not move past the stored value (when either is non-zero) is rejected as a cloned authenticator. The new counter is saved with a compare-and-set.
- Every rejection throws `InvalidPasskeyError` (400, `EC011`) with a `reason`.

## Phone code (OTP)

```ts
otp: { channel: "sms" /* or "whatsapp" */, phoneField: "phone", expiresIn: "5m", maxAttempts: 5 },
```

```ts
router.post("/auth/otp/request", async ({ request, response }) => {
  await requestOtp(User, request.input("phone"), { channel: request.input("via") === "whatsapp" ? "whatsapp" : "sms" });
  return response.success({ message: "If that number is registered, a code is on its way." });
}, { middleware: [otpRequestThrottleMiddleware()] }); // 3 / 1h per phone + IP

router.post("/auth/otp/verify", async ({ request, response }) => {
  const { tokens } = await verifyOtp(User, request.input("phone"), request.input("code"));
  authService.setAuthCookie(response, tokens.accessToken);
  return response.success({ ok: true });
}, { middleware: [otpVerifyThrottleMiddleware()] }); // 5 failures / 15m per phone + IP
```

- Codes have 6 digits and are stored in `one_time_tokens` (purpose `otp`) as a salted HMAC keyed from your access-token secret, never as plain SHA-256, which is trivially reversible for 6 digits. A new request invalidates the previous code.
- Every verify counts an attempt atomically first. After `maxAttempts` the code is invalidated, even if the right code comes next, and even under concurrent guesses.
- Delivery: `notify.channel(channel).send(phone, { body, code, expiresAt })`. Register that channel in `config/notifications.ts`, or set `auth.otp.send(phone, message, channel)`. `auth.otp.message(code)` changes the text.
- **Anti-enumeration:** an unknown phone gets the same `requestOtp` result (nothing sent) and the same `InvalidOneTimeTokenError` (400, `EC008`) from `verifyOtp`.
- CSRF: `verifyOtp` is a POST. If the route uses cookie auth, the 5.12 Origin check applies. Otherwise there is no ambient credential to ride.

## Gotchas

- `completeProviderLogin` needs the **same** response object to clear the state cookie. Do not pass a different one.
- One provider identity links to one account, of one user type.
- `auth.cleanup` hard-deletes expired and consumed `one_time_tokens` rows (challenges and codes included).
- The passkey specs run the real `@simplewebauthn/server` against a software ES256 authenticator, and the consume-once, OTP attempt cap, counter compare-and-set and provider-link uniqueness are proven on real MongoDB and Postgres. Google's token endpoint is still mocked, so test a real Google client before you ship.
- A counter the SDK rejects is reported with `reason: "counter-regression"`, the same as auth's own check.

## See also

- [`@warlock.js/auth/handle-login-and-logout/SKILL.md`](@warlock.js/auth/handle-login-and-logout/SKILL.md): password login and `setAuthCookie`
- [`@warlock.js/auth/throttle-login-attempts/SKILL.md`](@warlock.js/auth/throttle-login-attempts/SKILL.md): the throttle the OTP presets wrap
- [`@warlock.js/notifications/define-channel/SKILL.md`](@warlock.js/notifications/define-channel/SKILL.md): an SMS/WhatsApp channel
