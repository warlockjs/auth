import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import type { Auth } from "../auth.model";

/** Seal schema for a provider link. Exported so an override can extend it. */
export const providerAccountSchema = v.object({
  provider: v.string().required(),
  provider_user_id: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  email: v.string().optional(),
});

/**
 * Links a provider identity (`provider` + the provider's stable user id) to
 * an app user. Created the first time a VERIFIED provider email is matched or
 * a user is created for it; afterwards the link alone resolves the user, so a
 * later email change at the provider cannot move the login to another account.
 */
export class ProviderAccount extends Model {
  public static table = "provider_accounts";

  public static schema = providerAccountSchema;

  /** The linked user's id. */
  public get userId() {
    return this.get("user_id");
  }

  /** The linked user's type slug. */
  public get userType(): string {
    return this.get("user_type");
  }

  /** Find the link for a provider identity. */
  public static findLink(
    provider: string,
    providerUserId: string,
  ): Promise<ProviderAccount | null> {
    return this.first({ provider, provider_user_id: providerUserId });
  }

  /** Link a provider identity to a user. */
  public static link(provider: string, providerUserId: string, user: Auth, email?: string) {
    return this.create({
      provider,
      provider_user_id: providerUserId,
      user_id: user.id,
      user_type: user.userType,
      ...(email ? { email } : {}),
    });
  }
}
