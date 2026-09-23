import { config, type HttpContext, t, type Middleware, type Request } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import type {
  AuthCredentialDescriptor,
  AuthMiddlewareOptions,
  TokenFrom,
} from "../contracts/types";
import { AccessToken } from "../models/access-token";
import { authConfig } from "../services/auth-config";
import { authService } from "../services/auth.service";
import { isInvalidCredentialError, jwt } from "../services/jwt";
import { AuthErrorCodes } from "../utils/auth-error-codes";
import {
  assertCsrfOriginAllowed,
  CsrfOriginMismatchError,
  requiresCsrfOriginCheck,
} from "./csrf-origin-check";
import { localizedLoginPath } from "./localized-login-path";

/** The 401 body shape every rejection in this middleware carries. */
type UnauthorizedPayload = { error: string; errorCode: string };

/**
 * Reject an unauthenticated request, choosing the representation by ROUTE KIND.
 *
 * An API route always gets the JSON 401 it has always gotten. A PAGE route
 * (`request.route.isPage` — the React-SSR pages) instead redirects a logged-out
 * browser to the configured login path with a `returnUrl`, so a human
 * navigating to a guarded page lands on the login screen rather than reading a
 * raw JSON error blob — the defect in finding b9ab9804.
 *
 * The redirect is OPT-IN and backward-compatible: with no `auth.pageAuth.loginPath`
 * configured, even a page route falls back to the JSON 401, so an app that has
 * not asked for page-login UX keeps exactly its current behavior. The API 401
 * contract is never changed for API routes.
 *
 * `returnUrl` carries `request.url` — the relative path + query the browser was
 * on — never the absolute URL: a relative target cannot be turned into an
 * open-redirect off this app's origin.
 */
function rejectUnauthorized(
  { request, response }: HttpContext,
  payload: UnauthorizedPayload,
  redirect?: AuthMiddlewareOptions["redirect"],
) {
  const loginPath = redirect?.to ?? authConfig.pageAuth.loginPath();
  const returnUrlParam = redirect?.returnUrlParam ?? authConfig.pageAuth.returnUrlParam();

  if (loginPath && request.route?.isPage) {
    // Under an active `web.localeRouting` strategy, the login destination
    // itself must carry the request's locale prefix — otherwise an anonymous
    // `/ar/admin` bounces to the DEFAULT locale's `/login` rather than
    // `/ar/login`, even though `returnUrl` below correctly points back at
    // `/ar/admin`. See `./localized-login-path.ts`.
    const destination = localizedLoginPath(loginPath, request.locale);
    const separator = destination.includes("?") ? "&" : "?";
    const returnUrl = encodeURIComponent(request.url);

    return response.redirect(`${destination}${separator}${returnUrlParam}=${returnUrl}`);
  }

  return response.unauthorized(payload);
}

/**
 * Decoded access-token claims the middleware reads. The full payload carries
 * more (`created_at`, `tokenType`, `iat`, `exp`) but only these drive routing.
 */
type DecodedAccessToken = {
  id: string | number;
  userType?: string;
};

/**
 * Whether the persisted row says the token is dead.
 *
 * The answer belongs to the model (`AccessToken.isExpired`), so a registered
 * override that renames or reshapes its expiry column stays authoritative and
 * the middleware never touches a column name. A row that cannot answer at all —
 * an override that dropped the getter — is treated as **expired**: the failure
 * mode of this whole defect class was a check that quietly answered "fine" when
 * it had nothing to check, and that is not repeated here.
 *
 * This is independent of the `exp` claim required by `jwt.verify`. That guard
 * catches a token whose *claims* carry no deadline; this one catches a token
 * whose *row* says the deadline has passed — a logged-out or expired session
 * whose JWT is still within its own lifetime. Neither subsumes the other.
 */
function accessTokenRowIsExpired(accessToken: AccessToken): boolean {
  return typeof accessToken.isExpired === "boolean" ? accessToken.isExpired : true;
}

function readCredential(request: Request, tokenFrom: TokenFrom): string {
  if (tokenFrom === "header") {
    return request.authorizationValue;
  }

  const value = request.cookie(tokenFrom.slice("cookie:".length));

  return value ? String(value) : "";
}

function tokenFromDescriptor(descriptor: Partial<AuthCredentialDescriptor>): TokenFrom {
  if (!descriptor.source || descriptor.source === "header") return "header";

  if (!descriptor.key) {
    throw new Error("authMiddleware cookie credentials require a cookie key.");
  }

  return `cookie:${descriptor.key}`;
}

function resolveAllowedTypes(value: string | string[] | undefined): string[] {
  if (value !== undefined) return Array.isArray(value) ? value : [value];

  const configuredDefault = config.key("auth.defaultUserType") as string | undefined;

  if (configuredDefault) return [configuredDefault];

  const userTypes = config.key("auth.userType", {}) as Record<string, unknown>;
  const configuredTypes = Object.keys(userTypes);

  if (configuredTypes.length === 1) return configuredTypes;

  throw new Error(
    "authMiddleware requires a user type when auth.defaultUserType is unset and multiple user types exist.",
  );
}

/**
 * Build a route gate. Authentication is required unless optional is explicit.
 *
 * An omitted user type selects the configured default; an explicit argument
 * selects which user types may pass:
 * - `[]` — any authenticated user (token required, type not checked).
 * - `"admin"` / `["admin", "staff"]` — token required AND the user's
 *   `userType` must be one of the listed types.
 *
 * `{ optional: true }` allows anonymous requests. All other forms reject
 * missing or invalid credentials with 401, or a configured page redirect.
 *
 * `tokenFrom` selects one credential source and defaults to `"header"`.
 * A single source avoids making credential precedence depend on array order.
 *
 * @example
 * router.get("/account", authMiddleware([]), accountController);
 * router.get("/admin", authMiddleware("admin"), adminController);
 * router.get("/back-office", authMiddleware(["admin", "staff"]), backOfficeController);
 * router.get("/browser-account", authMiddleware([], "cookie:token"), accountController);
 */
export function authMiddleware(): Middleware;
export function authMiddleware(options: AuthMiddlewareOptions): Middleware;
export function authMiddleware(
  allowedUserType: string | string[],
  options?: AuthMiddlewareOptions,
): Middleware;
export function authMiddleware(
  allowedUserType: string | string[],
  tokenFrom?: TokenFrom,
): Middleware;
export function authMiddleware(
  userTypeOrOptions?: string | string[] | AuthMiddlewareOptions,
  legacyTokenFromOrOptions?: TokenFrom | AuthMiddlewareOptions,
): Middleware {
  const options =
    typeof userTypeOrOptions === "object" && !Array.isArray(userTypeOrOptions)
      ? userTypeOrOptions
      : typeof legacyTokenFromOrOptions === "object"
        ? legacyTokenFromOrOptions
        : undefined;
  const selectedUserType =
    typeof userTypeOrOptions === "string" || Array.isArray(userTypeOrOptions)
      ? userTypeOrOptions
      : undefined;
  const allowedTypes = resolveAllowedTypes(selectedUserType);
  const legacyTokenFrom =
    typeof legacyTokenFromOrOptions === "string" ? legacyTokenFromOrOptions : undefined;
  const tokenFrom = options ? tokenFromDescriptor(options) : (legacyTokenFrom ?? "header");
  const refreshCredential = options?.refresh ? tokenFromDescriptor(options.refresh) : undefined;
  const renewalUserType = allowedTypes.length === 1 ? allowedTypes[0] : undefined;

  if (
    refreshCredential &&
    (tokenFrom === "header" || refreshCredential === "header" || !renewalUserType)
  ) {
    throw new Error(
      "authMiddleware automatic renewal requires one allowed user type and cookie access and refresh credentials.",
    );
  }

  const optional = options?.optional === true;

  const auth: Middleware = async ({ request, response }) => {
    const reject = (payload: UnauthorizedPayload) =>
      rejectUnauthorized({ request, response }, payload, options?.redirect);
    let authorizationValue = readCredential(request, tokenFrom);
    let renewalAttempted = false;

    // Renewal can mint cookies, so a cookie-authenticated unsafe request must
    // pass the same CSRF check even when its access cookie is missing.
    if (
      (authorizationValue || refreshCredential) &&
      requiresCsrfOriginCheck(tokenFrom, request.method)
    ) {
      try {
        assertCsrfOriginAllowed(request);
      } catch (error) {
        if (!(error instanceof CsrfOriginMismatchError)) throw error;

        log.error("http", "auth", error);
        return response.forbidden({
          error: t("auth.errors.csrfOriginMismatch"),
          errorCode: AuthErrorCodes.CsrfOriginMismatch,
        });
      }
    }

    const renew = async (): Promise<boolean> => {
      if (!refreshCredential || renewalAttempted) return false;

      renewalAttempted = true;
      const refreshToken = readCredential(request, refreshCredential);
      if (!refreshToken) return false;

      const pair = await authService.renewAutomaticSession(refreshToken, renewalUserType!, {
        overlapMs: options?.refresh?.overlapMs,
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

    let decoded: DecodedAccessToken;
    let accessToken: AccessToken | null;

    // At most one renewal is attempted per request. The renewed access token
    // is checked through this normal path; no handler or unsafe request replay
    // is performed.
    while (true) {
      if (!authorizationValue) {
        request.locals.user = undefined;
        if (await renew()) continue;
        if (optional) return;
        return reject({
          error: t("auth.errors.missingAccessToken"),
          errorCode: AuthErrorCodes.MissingAccessToken,
        });
      }

      try {
        decoded = await jwt.verify<DecodedAccessToken>(authorizationValue);
      } catch (error) {
        if (!isInvalidCredentialError(error)) throw error;
        log.error("http", "auth", error);
        request.locals.user = undefined;
        if (await renew()) continue;
        if (optional) return;
        return reject({
          error: t("auth.errors.invalidAccessToken"),
          errorCode: AuthErrorCodes.InvalidAccessToken,
        });
      }

      request.decodedAccessToken = decoded;
      const AccessTokenModel = config.key("auth.accessToken.model", AccessToken);
      accessToken = await AccessTokenModel.findByToken(authorizationValue);

      if (!accessToken) {
        request.locals.user = undefined;
        if (await renew()) continue;
        if (optional) return;
        return reject({
          error: t("auth.errors.invalidAccessToken"),
          errorCode: AuthErrorCodes.InvalidAccessToken,
        });
      }

      if (accessTokenRowIsExpired(accessToken)) {
        await accessToken.destroy();
        request.locals.user = undefined;
        if (await renew()) continue;
        if (optional) return;
        return reject({
          error: t("auth.errors.invalidAccessToken"),
          errorCode: AuthErrorCodes.InvalidAccessToken,
        });
      }

      break;
    }
    const userType = decoded.userType ?? accessToken.userType;

    if (allowedTypes.length && !allowedTypes.includes(userType)) {
      return response.forbidden({
        error: t("auth.errors.unauthorized"),
        errorCode: AuthErrorCodes.Unauthorized,
      });
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
      request.locals.user = undefined;
      if (optional) return;

      return reject({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }

    if (!(await authService.canAuthenticate(currentUser))) {
      request.locals.user = undefined;
      if (optional) return;

      return reject({
        error: t("auth.errors.unauthorized"),
        errorCode: AuthErrorCodes.Unauthorized,
      });
    }

    request.locals.user = currentUser;
  };

  return auth;
}
