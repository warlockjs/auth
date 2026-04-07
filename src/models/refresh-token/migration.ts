import { migrate } from "@warlock.js/cascade";
import { RefreshToken } from "./refresh-token.model";

export const RefreshTokenMigration = migrate(RefreshToken, {
  name: "refreshToken",
  up() {
    // Create table
    this.createTableIfNotExists();

    // Primary key
    this.primaryUuid();

    // Token fields
    this.text("token").unique();
    this.uuid("user_id").index();
    this.string("user_type", 50).nullable();
    this.text("family_id").index().nullable();
    this.timestamp("expires_at").index().nullable();
    this.timestamp("last_used_at").nullable();
    this.timestamp("revoked_at").nullable();
    this.json("device_info").nullable();

    // Timestamps
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
