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

    // User reference (flat columns for cross-driver compatibility).
    // `foreignId` matches the DataSource's default primary-key type, so the
    // column stays compatible with the user model's `id` whether the app uses
    // integer (the default) or uuid PKs — hardcoding uuid here 500'd every
    // login on a default integer-PK app (finding 5e47bdb3).
    this.foreignId("user_id").index();
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
