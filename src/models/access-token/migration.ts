import { migrate } from "@warlock.js/cascade";
import { AccessToken } from "./access-token.model";

export const AccessTokenMigration = migrate(AccessToken, {
  name: "accessToken",
  up() {
    // Create table
    this.createTableIfNotExists();

    // Primary key
    this.primaryUuid();

    // Token field
    this.text("token").unique();
    this.timestamp("last_access").nullable();

    // User reference (flat columns for cross-driver compatibility)
    this.uuid("user_id").index();
    this.string("user_type", 50).nullable();

    // Status (for token revocation)
    this.boolean("is_active").nullable();

    // Timestamps
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
