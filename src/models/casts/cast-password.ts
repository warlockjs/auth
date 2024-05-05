import Password from "@mongez/password";
import type { Model } from "@warlock.js/cascade";

/**
 * Cast password on model save
 * If the password is not changed, keep it as is
 */
export function castPassword(value: any, column: string, model: Model) {
  return value
    ? Password.generate(String(value), 12)
    : model.getInitial(column);
}
