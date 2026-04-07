import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";

const refreshTokenSchema = v.object({
  token: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  family_id: v.string().required(),
  expires_at: v.date().required(),
  last_used_at: v.date().default(() => new Date()),
  revoked_at: v.date().optional(),
  device_info: v.record(v.any()).optional(),
});

export class RefreshToken extends Model {
  /**
   * {@inheritDoc}
   */
  public static table = "refresh_tokens";

  /**
   * {@inheritDoc}
   */
  public static schema = refreshTokenSchema;

  /**
   * Check if token is expired
   */
  public get isExpired(): boolean {
    const expiresAt = this.get("expires_at");
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  }

  /**
   * Check if token is revoked
   */
  public get isRevoked(): boolean {
    return !!this.get("revoked_at");
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
    return this.merge({ revoked_at: new Date() }).save();
  }

  /**
   * Mark token as used (update last_used_at)
   */
  public async markAsUsed(): Promise<void> {
    await this.merge({ last_used_at: new Date() }).save();
  }
}
