import { migrate } from "@warlock.js/cascade";
import { PasskeyCredential } from "./passkey-credential.model";

export const PasskeyCredentialMigration = migrate(PasskeyCredential, {
  name: "passkeyCredential",
  up() {
    this.createTableIfNotExists();

    this.primaryUuid();

    this.text("credential_id").unique();
    this.text("public_key");
    this.bigInteger("counter").default(0);
    this.json("transports").nullable();
    this.foreignId("user_id").index();
    this.string("user_type", 50).nullable();

    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});
