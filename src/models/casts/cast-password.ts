import { hash } from "@mongez/password";
import type { Model } from "@warlock.js/cascade";
import { config } from "@warlock.js/core";

/**
 * Cast password on model save
 * If the password is not changed, keep it as is
 */
export function castPassword(value: any, column: string, model: Model) {
  return value
    ? hash(String(value), config.key("auth.password.salt", 12))
    : model.getInitial(column);
}
