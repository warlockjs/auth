import type { ChildModel } from "@warlock.js/cascade";
import type { Request, Response } from "@warlock.js/core";
import type { AuthProvider } from "../contracts/providers";
import type { DeviceInfo, LoginResult } from "../contracts/types";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import type { Auth } from "../models/auth.model";
import { authConfig } from "../services/auth-config";
import { authService } from "../services/auth.service";
import { GoogleProvider } from "./google-provider";
import { safeEqual } from "../utils/safe-equal";
import { randomUrlSafe, takeProviderState, writeProviderState } from "./provider-state-cookie";
import { resolveProviderUser } from "./resolve-provider-user";

/**
 * Resolve a provider by name: `google` from `auth.providers.google`, anything
 * else from `auth.providers.custom`. Throws naming the config key when absent.
 */
export function resolveAuthProvider(name: string): AuthProvider {
  if (name === "google") {
    const google = authConfig.providers.google();

    if (google) return new GoogleProvider(google);
  } else {
    const custom = authConfig.providers.custom(name);

    if (custom) return custom;
  }

  throw new Error(
    `@warlock.js/auth: no login provider "${name}" — configure \`auth.providers.${
      name === "google" ? "google" : `custom.${name}`
    }\`.`,
  );
}

/**
 * Start a redirect login: generate `state`, `nonce` and a PKCE verifier, store
 * them in a signed 10-minute cookie, and resolve the provider URL to redirect
 * the browser to.
 *
 * @example
 * // GET /auth/google
 * export const googleRedirect: RequestHandler = async (_request, response) =>
 *   response.redirect(await startProviderLogin(response, "google"));
 */
export async function startProviderLogin(
  response: Response,
  providerName: string,
): Promise<string> {
  const provider = resolveAuthProvider(providerName);

  const state = {
    state: randomUrlSafe(),
    nonce: randomUrlSafe(),
    codeVerifier: randomUrlSafe(),
  };

  const url = await provider.authorizationUrl(state);

  writeProviderState(response, provider.name, state);

  return url;
}

/**
 * Finish a redirect login on the provider's callback: consume the state
 * cookie, reject a missing/forged/expired cookie, a cookie from another
 * provider, a provider-reported error or a `state` mismatch; let the provider
 * verify the callback; find-or-link the user; then log them in through
 * `authService.completeLogin` — the same outcome as password login.
 *
 * @throws InvalidProviderCallbackError (400, EC009) for any callback rejection.
 * @throws ProviderEmailNotVerifiedError (403, EC010) for an unlinked, unverified email.
 * @throws AuthProviderSdkMissingError when the provider's SDK is not installed.
 *
 * @example
 * // GET /auth/google/callback
 * const { user, tokens } = await completeProviderLogin(User, "google", request, response);
 * authService.setAuthCookie(response, tokens.accessToken);
 */
export async function completeProviderLogin<T extends Auth>(
  Model: ChildModel<T>,
  providerName: string,
  request: Request,
  response: Response,
  deviceInfo?: DeviceInfo,
): Promise<LoginResult<T>> {
  const provider = resolveAuthProvider(providerName);
  const expected = takeProviderState(request, response);

  if (!expected) {
    throw new InvalidProviderCallbackError("missing-or-invalid-state-cookie");
  }

  if (expected.provider !== provider.name) {
    throw new InvalidProviderCallbackError("state-cookie-for-another-provider");
  }

  const query: Record<string, unknown> = {
    code: request.input("code"),
    state: request.input("state"),
    error: request.input("error"),
  };

  if (query.error) {
    throw new InvalidProviderCallbackError(`provider-error:${String(query.error)}`);
  }

  if (typeof query.state !== "string" || !safeEqual(query.state, expected.state)) {
    throw new InvalidProviderCallbackError("state-mismatch");
  }

  const profile = await provider.handleCallback({
    query,
    expected: { state: expected.state, nonce: expected.nonce, codeVerifier: expected.codeVerifier },
  });

  const user = await resolveProviderUser(Model, profile);

  return authService.completeLogin(user, deviceInfo);
}
