import { migrationOffice } from "@warlock.js/cascade";
import { RefreshToken } from "./refresh-token";

export default migrationOffice.register({
  name: "refreshToken",
  blueprint: RefreshToken.blueprint(),
  up: (blueprint) => {
    blueprint.index("token");
    blueprint.index("userId");
    blueprint.index("familyId");
    blueprint.index("expiresAt");
  },
  down: (blueprint) => {
    blueprint.dropIndex("token");
    blueprint.dropIndex("userId");
    blueprint.dropIndex("familyId");
    blueprint.dropIndex("expiresAt");
  },
});
