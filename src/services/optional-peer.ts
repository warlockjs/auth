import { AuthProviderSdkMissingError } from "../errors/auth-provider-sdk-missing.error";

/**
 * Whether `error` (or an error it wraps as `cause`) is the resolver reporting
 * that `packageName` ITSELF is absent. A missing transitive dependency names
 * a different package and is not treated as "not installed".
 */
function isPackageMissing(error: unknown, packageName: string): boolean {
  for (let current = error, depth = 0; current && depth < 5; depth++) {
    const { code, message } = current as { code?: unknown; message?: unknown };

    if (
      (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
      typeof message === "string" &&
      message.includes(`'${packageName}'`)
    ) {
      return true;
    }

    current = (current as { cause?: unknown }).cause;
  }

  return false;
}

/**
 * Load an optional vendor SDK lazily. The specifier reaches `import()` as a
 * variable, so neither the type-checker nor a bundler ever requires the peer;
 * nothing is loaded until a login method actually runs.
 *
 * @param packageName - the optional peer, e.g. `"jose"`.
 * @param feature - the `warlock add` feature that installs it, e.g. `"auth-google"`.
 * @throws AuthProviderSdkMissingError when the package is not installed.
 */
export async function loadOptionalPeer<TModule extends object>(
  packageName: string,
  feature: string,
): Promise<TModule> {
  try {
    return (await import(packageName)) as TModule;
  } catch (error) {
    if (isPackageMissing(error, packageName)) {
      throw new AuthProviderSdkMissingError(packageName, feature, error);
    }

    throw error;
  }
}
