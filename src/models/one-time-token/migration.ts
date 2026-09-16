import { migrate } from "@warlock.js/cascade";
import { OneTimeToken } from "./one-time-token.model";

export const OneTimeTokenMigration = migrate(OneTimeToken, {
  name: "oneTimeToken",
  up() {
    this.createTableIfNotExists();

    this.primaryUuid();

    // SHA-256 hex digest of the raw token — the raw token is never stored.
    this.string("token_hash", 64).unique();
    this.string("purpose", 32);

    // `foreignId` follows the DataSource's default primary-key type, matching
    // the access/refresh token tables.
    this.foreignId("user_id").index();
    this.string("user_type", 50).nullable();

    this.timestamp("expires_at").index().nullable();
    this.timestamp("consumed_at").nullable();

    // Invalidating a user's previous reset tokens filters on these.
    this.index(["user_id", "user_type", "purpose"]);

    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
