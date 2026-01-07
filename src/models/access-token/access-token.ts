import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";

const accessTokenSchema = v.object({
  token: v.string().required(),
  lastAccess: v.date().default(() => new Date()),
  user: v
    .object({
      id: v.number().required(),
      userType: v.string(),
    })
    .allowUnknown()
    .required(),
});

export class AccessToken extends Model {
  /**
   * {@inheritDoc}
   */
  public static table = "accessTokens";

  public static schema = accessTokenSchema;
}
