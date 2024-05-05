import { migrationOffice } from "src/cascade";
import { AccessToken } from "./access-token";

export default migrationOffice.register({
  name: "accessToken",
  blueprint: AccessToken.blueprint(),
  up: blueprint => {
    blueprint.index("token");
  },
  down: blueprint => {
    blueprint.dropUniqueIndex("token");
  },
});
