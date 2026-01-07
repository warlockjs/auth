import { config, t, type Middleware, type Request, type Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { AccessToken } from "../models/access-token";
import { jwt } from "../services/jwt";
import { AuthErrorCodes } from "../utils/auth-error-codes";

export function authMiddleware(allowedUserType?: string | string[]) {
  const allowedTypes = !allowedUserType
    ? []
    : Array.isArray(allowedUserType)
      ? allowedUserType
      : [allowedUserType];

  const auth: Middleware = async (request: Request, response: Response) => {
    try {
      const authorizationValue = request.authorizationValue;

      if (!allowedTypes.length && !authorizationValue) return;

      if (!authorizationValue) {
        return response.unauthorized({
          error: t("auth.errors.missingAccessToken"),
          errorCode: AuthErrorCodes.MissingAccessToken,
        });
      }

      // get current user jwt
      const user = await jwt.verify(authorizationValue);

      // store decoded access token object in request object
      request.decodedAccessToken = user;
      // use our own jwt verify to verify the token
      const accessToken = await AccessToken.first({
        token: authorizationValue,
      });

      if (!accessToken) {
        return response.unauthorized({
          error: t("auth.errors.invalidAccessToken"),
          errorCode: AuthErrorCodes.InvalidAccessToken,
        });
      }

      // now, we need to get an instance of user using its corresponding model
      const userType = user.userType || accessToken.get("userType");

      // check if the user type is allowed
      if (allowedTypes.length && !allowedTypes.includes(userType)) {
        return response.unauthorized({
          error: t("auth.errors.unauthorized"),
          errorCode: AuthErrorCodes.Unauthorized,
        });
      }

      // get user model class
      const UserModel = config.key(`auth.userType.${userType}`);

      if (!UserModel) {
        throw new Error(`User type ${userType} is unknown type.`);
      }

      // get user model instance
      const currentUser = await UserModel.find(user.id);

      if (!currentUser) {
        accessToken.destroy();
        return response.unauthorized({
          error: t("auth.errors.invalidAccessToken"),
          errorCode: AuthErrorCodes.InvalidAccessToken,
        });
      }

      // update last access
      accessToken.set("lastAccess", new Date());
      await accessToken.save({ skipEvents: true });

      // set current user
      request.user = currentUser;
    } catch (err: any) {
      log.error("http", "auth", err);

      // unset current user
      request.clearCurrentUser();

      return response.unauthorized({
        error: t("auth.errors.invalidAccessToken"),
        errorCode: AuthErrorCodes.InvalidAccessToken,
      });
    }
  };

  return auth;
}
