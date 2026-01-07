import { migrate } from "@warlock.js/cascade";
import { RefreshToken } from "./refresh-token";

export default migrate(RefreshToken, {
  name: "refreshToken",
  up() {
    this.index("token");
    this.index("userId");
    this.index("familyId");
    this.index("expiresAt");
  },
  down() {
    this.dropIndex("token");
    this.dropIndex("userId");
    this.dropIndex("familyId");
    this.dropIndex("expiresAt");
  },
});
