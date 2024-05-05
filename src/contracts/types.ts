import { type Algorithm } from "fast-jwt";
import type { Auth } from "../models/auth";

export type AuthConfigurations = {
  /**
   * Define all user types
   * This is important to differentiate between user types when validating and generating tokens
   */
  userType: {
    [userType: string]: typeof Auth;
  };
  /**
   * JWT configurations
   */
  jwt: {
    secret: string;
    algorithm?: Algorithm;
    refresh?: {
      secret?: string;
      expiresIn?: number | string;
    };
  };
};
