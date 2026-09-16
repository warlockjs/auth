import { AccessTokenMigration } from "./access-token/migration";
import { OneTimeTokenMigration } from "./one-time-token/migration";
import { PasskeyCredentialMigration } from "./passkey-credential/migration";
import { ProviderAccountMigration } from "./provider-account/migration";
import { RefreshTokenMigration } from "./refresh-token/migration";

export * from "./access-token";
export * from "./auth.model";
export * from "./one-time-token";
export * from "./passkey-credential";
export * from "./provider-account";
export * from "./refresh-token";

export const authMigrations = [
  AccessTokenMigration,
  RefreshTokenMigration,
  OneTimeTokenMigration,
  ProviderAccountMigration,
  PasskeyCredentialMigration,
];
