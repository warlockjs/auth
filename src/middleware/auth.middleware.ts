import { config, t, type Middleware, type Request } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import type { TokenFrom } from "../contracts/types";
import { AccessToken } from "../models/access-token";
import { authService } from "../services/auth.service";
import { isInvalidCredentialError, jwt } from "../services/jwt";
import { AuthErrorCodes } from "../utils/auth-error-codes";

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

/**
 * Build a route gate that always requires an authenticated request.
 *
 * The argument is mandatory and selects which user types may pass:
 * - `[]` — any authenticated user (token required, type not checked).
 * - `"admin"` / `["admin", "staff"]` — token required AND the user's
 *   `userType` must be one of the listed types.
 *
 * There is no anonymous/optional mode: a request without a valid access
 * token is always rejected with `401`. Routes that should be public
 * simply omit the middleware.
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
export function authMiddleware(
  allowedUserType: string | string[],
  tokenFrom: TokenFrom = "header",
): Middleware {
  const allowedTypes = Array.isArray(allowedUserType) ? allowedUserType : [allowedUserType];

  const auth: Middleware = async ({ request, response }) => {
    const authorizationValue = readCredential(request, tokenFrom);

    if (!authorizationValue) {
      return response.unauthorized({
        error: t("auth.errors.missingAccessToken"),
        errorCode: AuthErrorCodes.MissingAccessToken,
      });
    }

    let decoded: DecodedAccessToken;

    // The ONLY try in this middleware, and it wraps a single call. Everything
    // after it is storage and configuration, where an exception means the
    // server is broken rather than the caller (D5).
    try {
      decoded = await jwt.verify<DecodedAccessToken>(authorizationValue);
    } catch (error) {
      if (!isInvalidCredentialError(error)) {
        // A DB/cache outage, a missing `JWT_SECRET`, or any other server-side
        // fault — not a verdict on this credential. Propagate to the request's
        // normal error path (a 500 monitoring can see) instead of answering
        // 401 and clearing the caller's session.
        throw error;
      }

      // A forged, malformed, expired token — or (D6) a `tokenType` mismatch —
      // is not an incident: it is a request carrying a credential the server
      // will never accept.
      log.error("http", "auth", error);

      request.clearCurrentUser();

      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }

    request.decodedAccessToken = decoded;

    // A valid signature is not enough — the token must still exist in storage,
    // so deleting the row (logout) invalidates it before its JWT expiry.
    const AccessTokenModel = config.key("auth.accessToken.model", AccessToken);
    const accessToken = await AccessTokenModel.findByToken(authorizationValue);

    if (!accessToken) {
      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }

    // ... and the row must still be live. Existence alone was the whole check
    // before 4.12.0, so a row whose own `expires_at` had passed still opened
    // the gate. The stored expiry is now enforced, and the dead row is
    // removed on the way out rather than left for the cleanup command.
    if (accessTokenRowIsExpired(accessToken)) {
      await accessToken.destroy();

      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }

    const userType = decoded.userType ?? accessToken.userType;

    if (allowedTypes.length && !allowedTypes.includes(userType)) {
      return response.unauthorized({
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

      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }

    if (!(await authService.canAuthenticate(currentUser))) {
      return response.unauthorized({
        error: t("auth.errors.unauthorized"),
        errorCode: AuthErrorCodes.Unauthorized,
      });
    }

    request.user = currentUser;
  };

  return auth;
}
