import type { Request, Response } from "@warlock.js/core";
import { createHmac, randomBytes } from "node:crypto";
import type { ProviderAuthorizationState } from "../contracts/providers";
import { authConfig } from "../services/auth-config";
import { safeEqual } from "../utils/safe-equal";

/** Cookie carrying a redirect login's state from the start to the callback. */
export const PROVIDER_STATE_COOKIE = "auth_provider_state";

/** How long a started provider login stays completable. */
const PROVIDER_STATE_TTL_SECONDS = 600;

/** What the signed cookie holds. */
export type StoredProviderState = ProviderAuthorizationState & {
  provider: string;
  expiresAt: number;
  callbackMode: "query" | "form_post";
};

/** 32 random bytes, base64url — used for `state`, `nonce` and the PKCE verifier. */
export function randomUrlSafe(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * HMAC over the payload with a key DERIVED from the access-token secret, so
 * the state cookie never shares a MAC key with the JWTs themselves.
 */
function sign(payload: string): string {
  const key = createHmac("sha256", authConfig.accessToken.secret())
    .update("@warlock.js/auth:provider-state")
    .digest();

  return createHmac("sha256", key).update(payload).digest("base64url");
}

/**
 * Write the signed, 10-minute state cookie for a provider login. `HttpOnly`
 * comes from the `response.cookie()` secure defaults. `callbackMode` picks
 * the `SameSite`/`Secure` pair: `"query"` (default) keeps the framework's
 * `SameSite=Lax`, which still rides a top-level GET redirect back to the app;
 * `"form_post"` (Apple) overrides to `SameSite=None; Secure`, since a browser
 * drops a `Lax` cookie on the provider's cross-site POST callback. Either
 * way, the signed `state`/`nonce`/PKCE values — not the cookie's SameSite
 * attribute — are what actually defend against CSRF here.
 */
export function writeProviderState(
  response: Response,
  provider: string,
  state: ProviderAuthorizationState,
  callbackMode: "query" | "form_post" = "query",
): void {
  const stored: StoredProviderState = {
    ...state,
    provider,
    expiresAt: Date.now() + PROVIDER_STATE_TTL_SECONDS * 1000,
    callbackMode,
  };
  const payload = Buffer.from(JSON.stringify(stored)).toString("base64url");

  response.cookie(PROVIDER_STATE_COOKIE, `${payload}.${sign(payload)}`, {
    raw: true,
    path: "/",
    maxAge: PROVIDER_STATE_TTL_SECONDS,
    ...(callbackMode === "form_post" ? { sameSite: "none", secure: true } : {}),
  });
}

/**
 * Read AND clear the state cookie, so a started login completes at most once.
 * Resolves `undefined` for an absent, forged (bad MAC), malformed or expired
 * cookie. The clearing `Set-Cookie` repeats whatever `SameSite`/`Secure` pair
 * the cookie was WRITTEN with (recovered from the decoded payload itself, so
 * this needs no mode passed in) — a browser only honours a clearing cookie
 * when it matches the original's attributes, and for a `form_post` (Apple)
 * cookie that means `SameSite=None; Secure` too, or the original survives.
 */
export function takeProviderState(
  request: Request,
  response: Response,
): StoredProviderState | undefined {
  const raw: unknown = request.cookie(PROVIDER_STATE_COOKIE);

  let stored: Partial<StoredProviderState> | undefined;

  if (typeof raw === "string") {
    const [payload, signature, ...rest] = raw.split(".");

    if (payload && signature && rest.length === 0 && safeEqual(signature, sign(payload))) {
      try {
        stored = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      } catch {
        stored = undefined;
      }
    }
  }

  response.clearCookie(PROVIDER_STATE_COOKIE, {
    path: "/",
    ...(stored?.callbackMode === "form_post" ? { sameSite: "none", secure: true } : {}),
  });

  if (
    typeof stored?.state !== "string" ||
    typeof stored.nonce !== "string" ||
    typeof stored.codeVerifier !== "string" ||
    typeof stored.provider !== "string" ||
    typeof stored.expiresAt !== "number" ||
    stored.expiresAt <= Date.now()
  ) {
    return undefined;
  }

  return stored as StoredProviderState;
}
