import { migrate } from "@warlock.js/cascade";
import { ProviderAccount } from "./provider-account.model";

export const ProviderAccountMigration = migrate(ProviderAccount, {
  name: "providerAccount",
  up() {
    this.createTableIfNotExists();

    this.primaryUuid();

    this.string("provider", 50);
    this.string("provider_user_id", 255);
    this.foreignId("user_id").index();
    this.string("user_type", 50).nullable();
    this.string("email", 255).nullable();

    // One app user per provider identity.
    this.unique(["provider", "provider_user_id"]);

    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
