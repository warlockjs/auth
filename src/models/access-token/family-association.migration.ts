import { migrate } from "@warlock.js/cascade";
import { AccessToken } from "./access-token.model";

/** Adds an optional family association without invalidating existing access tokens. */
export const AccessTokenFamilyAssociationMigration = migrate(AccessToken, {
  name: "accessTokenFamilyAssociation",
  up() {
    this.string("family_id", 64).nullable().index();
  },
  down() {
    this.dropColumn("family_id");
  },
});
