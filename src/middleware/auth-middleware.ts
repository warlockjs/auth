import config from "@mongez/config";
import type { Middleware, Request, Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { AccessToken } from "../models/access-token";
import { jwt } from "../services/jwt";

export function authMiddleware(allowedUserType?: string) {
  const auth: Middleware = async (request: Request, response: Response) => {
    try {
      const authorizationValue = request.authorizationValue;

      if (!authorizationValue) {
        return response.unauthorized({
          error: "Unauthorized: Access Token is missing",
        });
      }

      // get current user jwt
      const user = await jwt.verify(authorizationValue);

      // use our own jwt verify to verify the token
      const accessToken = await AccessToken.first({
        token: authorizationValue,
      });

      if (!accessToken) {
        return response.unauthorized({
          error: "Unauthorized: Invalid Access Token",
        });
      }

      // now, we need to get an instance of user using its corresponding model
      const userType = user.userType || accessToken.get("userType");

      // check if the user type is allowed
      if (allowedUserType && userType !== allowedUserType) {
        return response.unauthorized({
          error: "You are not allowed to access this resource",
        });
      }

      // get user model class
      const UserModel = config.get(`auth.userType.${userType}`);

      if (!UserModel) {
        throw new Error(`User type ${userType} is unknown type.`);
      }

      // get user model instance
      const currentUser = await UserModel.find(user.id);

      if (!currentUser) {
        accessToken.destroy();
        return response.unauthorized({
          error: "Unauthorized: Invalid Access Token",
        });
      }

      // set current user
      request.user = currentUser;
    } catch (err: any) {
      log.error("http", "auth", err);

      // unset current user
      request.clearCurrentUser();

      return response.unauthorized({
        error: "Unauthorized: Invalid Access Token",
      });
    }
  };

  if (allowedUserType) {
    const userAccessTokenKey = `${allowedUserType}AccessToken`;
    const userAccessTokenKeyNameHeader = `${allowedUserType}AccessTokenHeader`;
    (auth as any).postman = {
      onCollectingVariables(variables: any) {
        if (
          variables.find(
            (variable: any) => variable.key === userAccessTokenKeyNameHeader,
          )
        )
          return;

        variables.push({
          key: userAccessTokenKey,
          value: "YOUR_TOKEN_HERE",
        });

        variables.push({
          key: userAccessTokenKeyNameHeader,
          value: `Bearer {{${userAccessTokenKey}}}`,
        });
      },
      onAddingRequest({ request }: any) {
        request.header.push({
          key: "Authorization",
          value: `{{${userAccessTokenKeyNameHeader}}}`,
        });
      },
    };
  }

  return auth;
}
