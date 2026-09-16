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
 * Write the signed, 10-minute state cookie for a provider login. Attribute
 * flags (`HttpOnly`, `SameSite=Lax`, `Secure` outside dev) come from the
 * `response.cookie()` secure defaults; `Lax` still rides the provider's
 * top-level GET redirect back to the app.
 */
export function writeProviderState(
  response: Response,
  provider: string,
  state: ProviderAuthorizationState,
): void {
  const stored: StoredProviderState = {
    ...state,
    provider,
    expiresAt: Date.now() + PROVIDER_STATE_TTL_SECONDS * 1000,
  };
  const payload = Buffer.from(JSON.stringify(stored)).toString("base64url");

  response.cookie(PROVIDER_STATE_COOKIE, `${payload}.${sign(payload)}`, {
    raw: true,
    path: "/",
    maxAge: PROVIDER_STATE_TTL_SECONDS,
  });
}

/**
 * Read AND clear the state cookie, so a started login completes at most once.
 * Resolves `undefined` for an absent, forged (bad MAC), malformed or expired
 * cookie.
 */
export function takeProviderState(
  request: Request,
  response: Response,
): StoredProviderState | undefined {
  const raw: unknown = request.cookie(PROVIDER_STATE_COOKIE);

  response.clearCookie(PROVIDER_STATE_COOKIE, { path: "/" });

  if (typeof raw !== "string") return undefined;

  const [payload, signature, ...rest] = raw.split(".");

  if (!payload || !signature || rest.length > 0 || !safeEqual(signature, sign(payload))) {
    return undefined;
  }

  let stored: Partial<StoredProviderState> | undefined;

  try {
    stored = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }

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
