import { config, type Request, type Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import type { TokenFrom } from "../contracts/types";
import { AccessToken } from "../models/access-token";
import { authService } from "./auth.service";
import { isInvalidCredentialError, jwt } from "./jwt";

/**
 * Decoded access-token claims the resolver reads. The full payload carries
 * more (`created_at`, `tokenType`, `iat`, `exp`) but only these drive routing.
 */
type DecodedAccessToken = {
  id: string | number;
  userType?: string;
};

export type ResolveRequestUserOptions = {
  /** Where the access token is read from. Defaults to `"header"`. */
  tokenFrom?: TokenFrom;
  /** Refresh credential source; enables one automatic renewal per call. */
  refreshCredential?: TokenFrom;
  /** Refresh overlap window forwarded to `authService.renewAutomaticSession`. */
  overlapMs?: number;
  /** User types allowed to pass. Empty means any authenticated type. */
  allowedTypes?: string[];
  /** Absolute family lifetime in ms; rotation never extends a family past it. */
  maxAgeMs?: number;
  /** The single user type a renewal mints for. Required for renewal. */
  renewalUserType?: string;
};

/**
 * Why a request did not resolve to a user. The middleware maps each reason to
 * its own response; `resolveRequestUser` collapses them all to `null`.
 */
export type RequestUserFailure = "missing" | "invalid" | "forbidden" | "unauthorized";

export type RequestUserOutcome<TUser = any> =
  | { user: TUser; failure?: undefined }
  | { user: null; failure: RequestUserFailure };

/**
 * Whether the persisted row says the token is dead.
 *
 * The answer belongs to the model (`AccessToken.isExpired`), so a registered
 * override that renames or reshapes its expiry column stays authoritative. A
 * row that cannot answer at all — an override that dropped the getter — is
 * treated as **expired**: a check must never quietly answer "fine" when it has
 * nothing to check.
 *
 * This is independent of the `exp` claim required by `jwt.verify`: that guard
 * catches a token whose *claims* carry no deadline; this one catches a token
 * whose *row* says the deadline has passed.
 */
function accessTokenRowIsExpired(accessToken: AccessToken): boolean {
  return typeof accessToken.isExpired === "boolean" ? accessToken.isExpired : true;
}

/** Read one credential (access or refresh) from the header or a cookie. */
export function readCredential(request: Request, tokenFrom: TokenFrom): string {
  if (tokenFrom === "header") {
    return request.authorizationValue;
  }

  const value = request.cookie(tokenFrom.slice("cookie:".length));

  return value ? String(value) : "";
}

/**
 * Resolve a request's credential to a user, reporting WHY it failed.
 *
 * Side effects match what `authMiddleware` always did: `request.locals.user` is
 * cleared on every failure, `request.decodedAccessToken` is set once a token
 * verifies, and stale rows are destroyed. It does NOT set `request.locals.user`
 * on success — the caller decides that.
 *
 * At most one renewal is attempted per call. The renewed access token is
 * checked through the same path; no handler or unsafe request replay happens.
 */
export async function resolveRequestUserOutcome(
  request: Request,
  response: Response,
  options: ResolveRequestUserOptions = {},
): Promise<RequestUserOutcome> {
  const tokenFrom = options.tokenFrom ?? "header";
  const allowedTypes = options.allowedTypes ?? [];
  const { refreshCredential } = options;
  let authorizationValue = readCredential(request, tokenFrom);
  let renewalAttempted = false;

  const renew = async (): Promise<boolean> => {
    if (!refreshCredential || renewalAttempted) return false;

    renewalAttempted = true;
    const refreshToken = readCredential(request, refreshCredential);
    if (!refreshToken) return false;

    const pair = await authService.renewAutomaticSession(refreshToken, options.renewalUserType!, {
      overlapMs: options.overlapMs,
      maxAgeMs: options.maxAgeMs,
    });
    if (!pair?.refreshToken) return false;

    authService.setAuthCookie(response, pair.accessToken, {
      name: tokenFrom.slice("cookie:".length),
    });
    authService.setAuthCookie(response, pair.refreshToken, {
      name: refreshCredential.slice("cookie:".length),
    });
    authorizationValue = pair.accessToken.token;

    return true;
  };

  const fail = (failure: RequestUserFailure): RequestUserOutcome => {
    request.locals.user = undefined;

    return { user: null, failure };
  };

  let decoded: DecodedAccessToken;
  let accessToken: AccessToken | null;

  while (true) {
    if (!authorizationValue) {
      request.locals.user = undefined;
      if (await renew()) continue;
      return fail("missing");
    }

    try {
      decoded = await jwt.verify<DecodedAccessToken>(authorizationValue);
    } catch (error) {
      if (!isInvalidCredentialError(error)) throw error;
      log.error("http", "auth", error);
      request.locals.user = undefined;
      if (await renew()) continue;
      return fail("invalid");
    }

    request.decodedAccessToken = decoded;
    const AccessTokenModel = config.key("auth.accessToken.model", AccessToken);
    accessToken = await AccessTokenModel.findByToken(authorizationValue);

    if (!accessToken) {
      request.locals.user = undefined;
      if (await renew()) continue;
      return fail("invalid");
    }

    if (accessTokenRowIsExpired(accessToken)) {
      await accessToken.destroy();
      request.locals.user = undefined;
      if (await renew()) continue;
      return fail("invalid");
    }

    break;
  }

  const userType = decoded.userType ?? accessToken.userType;

  if (allowedTypes.length && !allowedTypes.includes(userType)) {
    return { user: null, failure: "forbidden" };
  }

  const UserModel = config.key(`auth.userType.${userType}`);

  if (!UserModel) {
    // Configuration, not credentials. Throwing keeps a mis-registered app
    // loudly broken instead of quietly rejecting every request of this type.
    throw new Error(`User type ${userType} is unknown type.`);
  }

  const currentUser = await UserModel.find(decoded.id);

  if (!currentUser) {
    await accessToken.destroy();

    return fail("invalid");
  }

  if (!(await authService.canAuthenticate(currentUser))) {
    return fail("unauthorized");
  }

  return { user: currentUser };
}

/**
 * Resolve the request's credential to its user model, or `null` when there is
 * none (missing, invalid, expired, wrong type, or not allowed to authenticate).
 *
 * Includes the middleware's automatic renewal when `options.refreshCredential`
 * is set. Use `resolveRequestUserOutcome` when the failure reason matters.
 */
export function resolveRequestUser(
  request: Request,
  response: Response,
  options: ResolveRequestUserOptions = {},
): Promise<any> {
  // Single-flight: the PROMISE is stored, so concurrent and repeat callers in
  // one request share one verify, one lookup and at most one renewal. The first
  // caller's options win for the rest of the request.
  if (!request.locals.session) {
    request.locals.session = resolveRequestUserOutcome(request, response, options).then(
      outcome => outcome.user,
    );
  }

  return request.locals.session;
}
