import { migrate } from "@warlock.js/cascade";
import { AccessToken } from "./access-token";

export default migrate(AccessToken, {
  name: "accessToken",
  up() {
    this.string("accessToken").index();
    this.date("lastAccess");
  },
  down() {
    this.dropIndex("token");
  },
});
