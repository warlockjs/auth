import { migrate } from "@warlock.js/cascade";
import { AccessToken } from "./access-token.model";

export const AccessTokenMigration = migrate(AccessToken, {
  name: "accessToken",
  up() {
    // Create table
    this.createTableIfNotExists();

    // Primary key
    this.id();

    // Token field
    this.string("token", 500).unique();
    this.timestamp("lastAccess").nullable();

    // Embedded user info (JSONB)
    this.json("user");

    // Status (for token revocation)
    this.boolean("isActive").default(true);

    // Timestamps
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
