import { AccessTokenMigration } from "./access-token/migration";
import { RefreshTokenMigration } from "./refresh-token/migration";

export * from "./access-token";
export * from "./auth";
export * from "./refresh-token";

export const authMigrations = [AccessTokenMigration, RefreshTokenMigration];
