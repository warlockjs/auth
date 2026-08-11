import { config, t, type Middleware, type Request, type Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { AccessToken } from "../models/access-token";
import { jwt } from "../services/jwt";
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
 * @example
 * router.get("/account", authMiddleware([]), accountController);
 * router.get("/admin", authMiddleware("admin"), adminController);
 * router.get("/back-office", authMiddleware(["admin", "staff"]), backOfficeController);
 */
export function authMiddleware(allowedUserType: string | string[]) {
  const allowedTypes = Array.isArray(allowedUserType) ? allowedUserType : [allowedUserType];

  const auth: Middleware = async (request: Request, response: Response) => {
    try {
      const authorizationValue = request.authorizationValue;

      if (!authorizationValue) {
        return response.unauthorized({
          error: t("auth.errors.missingAccessToken"),
          errorCode: AuthErrorCodes.MissingAccessToken,
        });
      }

      const decoded = await jwt.verify<DecodedAccessToken>(authorizationValue);

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

      request.user = currentUser;
    } catch (error: any) {
      log.error("http", "auth", error);

      request.clearCurrentUser();

      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }
  };

  return auth;
}
