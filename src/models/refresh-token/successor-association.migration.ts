import { migrate } from "@warlock.js/cascade";
import { RefreshToken } from "./refresh-token.model";

/** Adds nullable successor links for bounded concurrent refresh coalescing. */
export const RefreshTokenSuccessorAssociationMigration = migrate(RefreshToken, {
  name: "refreshTokenSuccessorAssociation",
  up() {
    this.uuid("successor_access_token_id").nullable().index();
    this.uuid("successor_refresh_token_id").nullable().index();
  },
  down() {
    this.dropIndex("successor_access_token_id");
    this.dropIndex("successor_refresh_token_id");
    this.dropColumn("successor_access_token_id");
    this.dropColumn("successor_refresh_token_id");
  },
});
