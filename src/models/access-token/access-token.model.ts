import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";

const accessTokenSchema = v.object({
  token: v.string().required(),
  last_access: v.date().defaultNow().optional(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  is_active: v.boolean().default(true),
});

export class AccessToken extends Model {
  /**
   * {@inheritDoc}
   */
  public static table = "access_tokens";

  public static schema = accessTokenSchema;
}
