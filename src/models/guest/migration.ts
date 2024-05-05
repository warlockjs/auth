import { Guest } from "./guest";

export const guestBlueprint = Guest.blueprint();

export async function guestMigration() {
  await guestBlueprint.unique("id");
}

guestMigration.down = async () => {
  await guestBlueprint.dropUniqueIndex("id");
};

guestMigration.blueprint = guestBlueprint;
