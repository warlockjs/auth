import type { ChildModel } from "@warlock.js/cascade";
import type { ProviderProfile } from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { ProviderEmailNotVerifiedError } from "../errors/provider-email-not-verified.error";
import type { Auth } from "../models/auth.model";
import { ProviderAccount } from "../models/provider-account";
import { authConfig } from "../services/auth-config";

/** Default creation for a first provider login: email, name, and the verified stamp. */
async function createUserFor<T extends Auth>(
  Model: ChildModel<T>,
  profile: ProviderProfile,
): Promise<T> {
  const createUser = authConfig.providers.createUser();

  if (createUser) {
    return (await createUser(profile, Model as unknown as ChildModel<Auth>)) as T;
  }

  return (await Model.create({
    [authConfig.providers.emailField()]: profile.email,
    ...(profile.name ? { name: profile.name } : {}),
    // The provider verified this address; record it the way verifyEmail does.
    [authConfig.verification.field()]: new Date(),
  } as never)) as T;
}

/**
 * Find or create the app user for a provider profile, and link them.
 *
 * 1. An existing `provider_accounts` link wins — the provider's stable id, not
 *    the email, identifies the account from then on.
 * 2. Otherwise the provider email MUST be verified. An unverified (or absent)
 *    email throws {@link ProviderEmailNotVerifiedError} and nothing is linked
 *    or created: linking on it would let anyone who can add an unverified
 *    address at the provider take over the matching account.
 * 3. Verified: the user whose `auth.providers.emailField` matches, else a new
 *    user (`auth.providers.createUser`, or the default) — then the link is stored.
 */
export async function resolveProviderUser<T extends Auth>(
  Model: ChildModel<T>,
  profile: ProviderProfile,
): Promise<T> {
  const link = await ProviderAccount.findLink(profile.provider, profile.providerUserId);

  if (link) {
    const linked = (await Model.find(link.userId)) as T | null;

    if (!linked || linked.userType !== link.userType) {
      throw new InvalidProviderCallbackError("link-points-to-missing-user");
    }

    return linked;
  }

  if (!profile.emailVerified || !profile.email) {
    throw new ProviderEmailNotVerifiedError();
  }

  const existing = (await Model.first({
    [authConfig.providers.emailField()]: profile.email,
  })) as T | null;

  const user = existing ?? (await createUserFor(Model, profile));

  await ProviderAccount.link(profile.provider, profile.providerUserId, user, profile.email);

  return user;
}
