import { migrationOffice } from "src/cascade";
import { Guest } from "./guest";

export default migrationOffice.register({
  name: "guest",
  blueprint: Guest.blueprint(),
  up: blueprint => {
    blueprint.index("id");
  },
  down: blueprint => {
    blueprint.dropUniqueIndex("id");
  },
});
