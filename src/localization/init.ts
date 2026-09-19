import { registerAuthTranslations } from "./register-auth-translations";

// Side-effect module: importing `@warlock.js/auth` registers its default
// translations, so `t("auth.errors.*")` never returns the raw key.
registerAuthTranslations();
