import { migrate } from "@warlock.js/cascade";
import { AuthTokenFamily } from "./auth-token-family.model";

/** Creates the durable authority shared by every token in a refresh family. */
export const AuthTokenFamilyMigration = migrate(AuthTokenFamily, {
  name: "authTokenFamily",
  up() {
    this.createTableIfNotExists();
    this.primaryUuid();
    this.string("family_id", 64).unique();
    this.foreignId("user_id").index();
    this.string("user_type", 50).nullable();
    this.integer("revision").default(0);
    this.timestamp("revoked_at").nullable();
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
