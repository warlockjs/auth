/**
 * Spec-only stand-in for the slice of `@warlock.js/core` the login-provider
 * code touches: `config.key` over a mutable map, and the HTTP error classes.
 */
export function fakeCoreModule(configValues: Record<string, unknown>) {
  class HttpError extends Error {
    public constructor(
      public status: number,
      message: string,
      public payload?: unknown,
    ) {
      super(message);
    }
  }

  const httpError = (status: number) =>
    class extends HttpError {
      public constructor(message: string, payload?: unknown) {
        super(status, message, payload);
      }
    };

  return {
    config: {
      key: (key: string, fallback?: unknown) =>
        key in configValues ? configValues[key] : fallback,
      get: (key: string, fallback?: unknown) =>
        key in configValues ? configValues[key] : fallback,
    },
    t: (key: string) => key,
    HttpError,
    BadRequestError: httpError(400),
    ForbiddenError: httpError(403),
    ServerError: httpError(500),
  };
}
