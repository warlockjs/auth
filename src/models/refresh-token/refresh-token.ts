import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";

const refreshTokenSchema = v.object({
  token: v.string().required(),
  userId: v.number().required(),
  userType: v.string().required(),
  familyId: v.string().required(),
  expiresAt: v.date().required(),
  lastUsedAt: v.date().default(() => new Date()),
  revokedAt: v.date(),
  deviceInfo: v.record(v.any()),
});

export class RefreshToken extends Model {
  /**
   * {@inheritDoc}
   */
  public static table = "refreshTokens";

  /**
   * {@inheritDoc}
   */
  public static schema = refreshTokenSchema;

  /**
   * Check if token is expired
   */
  public get isExpired(): boolean {
    const expiresAt = this.get("expiresAt");
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  }

  /**
   * Check if token is revoked
   */
  public get isRevoked(): boolean {
    return !!this.get("revokedAt");
  }

  /**
   * Check if token is valid (not expired and not revoked)
   */
  public get isValid(): boolean {
    return !this.isExpired && !this.isRevoked;
  }

  /**
   * Revoke this token
   */
  public async revoke(): Promise<this> {
    return this.merge({ revokedAt: new Date() }).save();
  }

  /**
   * Mark token as used (update lastUsedAt)
   */
  public async markAsUsed(): Promise<void> {
    await this.merge({ lastUsedAt: new Date() }).save();
  }
}
