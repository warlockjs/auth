import { AccessTokenBlueprint } from "./access-token";

export async function accessTokenMigration() {
  AccessTokenBlueprint.unique("token");
}

accessTokenMigration.down = async () => {
  AccessTokenBlueprint.dropUniqueIndex("token");
};

accessTokenMigration.blueprint = AccessTokenBlueprint;
