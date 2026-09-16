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
    // the access/refresh token tables. Nullable only for a passkey
    // authentication challenge, which is issued before anyone is identified.
    this.foreignId("user_id").nullable().index();
    this.string("user_type", 50).nullable();

    this.timestamp("expires_at").index().nullable();
    this.timestamp("consumed_at").nullable();

    // Failed verify attempts — only OTP codes are capped on it.
    this.integer("attempts").default(0);

    // Invalidating a user's previous reset tokens filters on these.
    this.index(["user_id", "user_type", "purpose"]);

    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
