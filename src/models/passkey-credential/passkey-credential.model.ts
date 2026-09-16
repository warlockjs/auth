import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import type { Auth } from "../auth.model";

/** Seal schema for a stored passkey. Exported so an override can extend it. */
export const passkeyCredentialSchema = v.object({
  credential_id: v.string().required(),
  public_key: v.string().required(),
  counter: v.int().required(),
  transports: v.array(v.string()).optional(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
});

/**
 * A registered WebAuthn credential. `credential_id` and `public_key` are
 * base64url; `counter` is the last signature counter seen, which an
 * authentication must advance (a clone detector).
 */
export class PasskeyCredential extends Model {
  public static table = "passkey_credentials";

  public static schema = passkeyCredentialSchema;

  /** base64url credential id. */
  public get credentialId(): string {
    return this.get("credential_id");
  }

  /** Last signature counter seen. */
  public get counter(): number {
    return Number(this.get("counter") ?? 0);
  }

  /** The owner's id. */
  public get userId() {
    return this.get("user_id");
  }

  /** The owner's type slug. */
  public get userType(): string {
    return this.get("user_type");
  }

  /** Find a credential by its base64url id. */
  public static findByCredentialId(credentialId: string): Promise<PasskeyCredential | null> {
    return this.first({ credential_id: credentialId });
  }

  /** Every credential the user registered. */
  public static listFor(user: Auth): Promise<PasskeyCredential[]> {
    return this.query().where({ user_id: user.id, user_type: user.userType }).get();
  }

  /**
   * Store `newCounter` ONLY if the row still holds `expected` — a compare-and-set,
   * so two concurrent assertions with the same counter cannot both succeed.
   */
  public async advanceCounter(expected: number, newCounter: number): Promise<boolean> {
    const modelClass = this.constructor as typeof PasskeyCredential;

    const updated = await modelClass.atomic(
      { id: this.id, counter: expected },
      { $set: { counter: newCounter } },
    );

    return updated > 0;
  }
}
