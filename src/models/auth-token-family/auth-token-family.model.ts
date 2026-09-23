import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import type { Auth } from "../auth.model";

/** Durable revision authority for one refresh-token rotation family. */
export const authTokenFamilySchema = v.object({
  family_id: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  revision: v.number().default(0),
  revoked_at: v.date().optional(),
});

/** Coordinates family-wide refresh, replay containment, and logout transitions. */
export class AuthTokenFamily extends Model {
  public static table = "auth_token_families";

  public static schema = authTokenFamilySchema;

  /** Whether a family-wide revoke has made every member unusable. */
  public get isRevoked(): boolean {
    return Boolean(this.get("revoked_at"));
  }

  /** Create the durable family record before its first token pair is issued. */
  public static issue(user: Auth, familyId: string) {
    return this.create({
      family_id: familyId,
      user_id: user.id,
      user_type: user.userType,
      revision: 0,
    });
  }

  public static findByFamilyId(familyId: string): Promise<AuthTokenFamily | null> {
    return this.first({ family_id: familyId });
  }

  /** Add a durable row for an existing lineage through a driver-native upsert. */
  public static async ensure(user: Auth, familyId: string): Promise<AuthTokenFamily> {
    await this.atomic(
      { family_id: familyId },
      { $setOnInsert: { user_id: user.id, user_type: user.userType, revision: 0 } },
      { upsert: true },
    );

    const family = await this.findByFamilyId(familyId);

    if (!family) throw new Error("Token family upsert did not return a family");

    if (family.get("user_id") !== user.id || family.get<string>("user_type") !== user.userType) {
      throw new Error("Token family belongs to a different user");
    }

    return family;
  }

  /** Every non-revoked family for a user, including a rotated refresh row. */
  public static activeFor(user: Auth): Promise<AuthTokenFamily[]> {
    return this.query()
      .where({ user_id: user.id, user_type: user.userType, revoked_at: null })
      .get();
  }

  /**
   * Compare-and-set the family revision. A zero result is a concurrent family
   * transition, never a successful no-op.
   */
  public static advanceRevision(familyId: string, expectedRevision: number): Promise<number> {
    return this.atomic(
      { family_id: familyId, revision: expectedRevision, revoked_at: null },
      { $inc: { revision: 1 } },
    );
  }

  /** Stamp the durable family revoke marker after a successful CAS. */
  public static revoke(familyId: string, expectedRevision: number): Promise<number> {
    return this.atomic(
      { family_id: familyId, revision: expectedRevision + 1, revoked_at: null },
      { $set: { revoked_at: new Date() } },
    );
  }
}
