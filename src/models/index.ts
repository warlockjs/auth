import { AccessTokenFamilyAssociationMigration } from "./access-token/family-association.migration";
import { AccessTokenMigration } from "./access-token/migration";
import { AuthTokenFamilyMigration } from "./auth-token-family/migration";
import { OneTimeTokenMigration } from "./one-time-token/migration";
import { PasskeyCredentialMigration } from "./passkey-credential/migration";
import { ProviderAccountMigration } from "./provider-account/migration";
import { RefreshTokenMigration } from "./refresh-token/migration";
import { RefreshTokenSuccessorAssociationMigration } from "./refresh-token/successor-association.migration";

export * from "./access-token";
export * from "./auth-token-family";
export * from "./auth.model";
export * from "./one-time-token";
export * from "./passkey-credential";
export * from "./provider-account";
export * from "./refresh-token";

export const authMigrations = [
  AccessTokenMigration,
  AccessTokenFamilyAssociationMigration,
  RefreshTokenMigration,
  RefreshTokenSuccessorAssociationMigration,
  AuthTokenFamilyMigration,
  OneTimeTokenMigration,
  ProviderAccountMigration,
  PasskeyCredentialMigration,
];
