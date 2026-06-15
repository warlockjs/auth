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

    // User reference (flat columns for cross-driver compatibility)
    this.uuid("user_id").index();
    this.string("user_type", 50).nullable();

    // Expiry — enables server-side cleanup of stale access-token rows
    this.timestamp("expires_at").index().nullable();

    // Timestamps
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
