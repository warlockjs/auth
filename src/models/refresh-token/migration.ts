import { migrate } from "@warlock.js/cascade";
import { RefreshToken } from "./refresh-token.model";

export const RefreshTokenMigration = migrate(RefreshToken, {
  name: "refreshToken",
  up() {
    // Create table
    this.createTableIfNotExists();

    // Primary key
    this.id();

    // Token fields
    this.string("token", 500).unique();
    this.integer("userId").index();
    this.string("userType", 50);
    this.string("familyId", 100).index();
    this.timestamp("expiresAt").index();
    this.timestamp("lastUsedAt").nullable();
    this.timestamp("revokedAt").nullable();
    this.json("deviceInfo").nullable();

    // Timestamps
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
