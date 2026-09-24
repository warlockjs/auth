import { config, t, type Middleware, type Request, type Response } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import ms from "ms";
import {
  assertCsrfOriginAllowed,
  CsrfOriginMismatchError,
  requiresCsrfOriginCheck,
} from "../middleware/csrf-origin-check";
import { authConfig } from "../services/auth-config";
import { resolveRequestUser } from "../services/resolve-request-user";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/** Credential sources a session can be read from. */
export type SessionSource = "cookie" | "header";

/** Absolute family lifetime used when `session.maxAge` is not configured. */
const DEFAULT_SESSION_MAX_AGE = "30d";

/**
 * The seam web consumes. Declared here, not imported: web and auth never
 * depend on each other, and `pageSession()` satisfies web's `SessionResolver`
 * structurally.
 */
export type PageSessionResolver<TModel = unknown, TUser = unknown> = {
  resolve(request: Request, response: Response): Promise<{ model: TModel; user: TUser } | null>;
};

export type SessionResolverOptions = {
  /** Access cookie name. @default auth.cookie.name */
  cookie?: string;
  /** Refresh cookie name. @default auth.cookie.refreshName */
  refreshCookie?: string;
  /** Credential sources. A present Authorization header always wins. @default ["cookie", "header"] */
  sources?: SessionSource[];
  /** Renew an expired access cookie from the refresh cookie. Cookie source only. @default true */
  renew?: boolean;
  /** Allowed user types. @default auth.defaultUserType */
  userTypes?: string | string[];
  /** Absolute family lifetime, an `ms` string or milliseconds. @default auth.session.maxAge, else "30d" */
  maxAge?: string | number;
  /** Refresh overlap window forwarded to renewal. */
  overlapMs?: number;
};

export type PageSessionOptions<TModel, TUser> = SessionResolverOptions & {
  /** Model → wire projection. Required: a model never crosses the wire by default. */
  project: (model: TModel) => TUser | Promise<TUser>;
};

export type SessionMiddlewareOptions = SessionResolverOptions & {
  /** Let guests through with no user instead of a 401. @default false */
  optional?: boolean;
};

function resolveMaxAgeMs(maxAge: string | number | undefined): number {
  const raw = maxAge ?? config.key("auth.session.maxAge", DEFAULT_SESSION_MAX_AGE);
  const parsed = typeof raw === "number" ? raw : ms(raw as ms.StringValue);

  if (typeof parsed !== "number" || !Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(
      `session.maxAge: ${JSON.stringify(raw)} is not a valid ms duration — use a positive duration such as "30d".`,
    );
  }

  return parsed;
}

function resolveUserTypes(value: string | string[] | undefined): string[] {
  if (value !== undefined) return Array.isArray(value) ? value : [value];

  const configured = config.key("auth.defaultUserType");

  return configured ? [configured as string] : [];
}

/**
 * The shared "credential → model" step behind `pageSession` and
 * `sessionMiddleware`. Resolved once per request through
 * `resolveRequestUser`'s single-flight memo.
 */
function createModelResolver(options: SessionResolverOptions) {
  const sources = options.sources?.length ? options.sources : (["cookie", "header"] as const);
  const useHeader = sources.includes("header");
  const useCookie = sources.includes("cookie");
  const renew = options.renew ?? true;

  const resolveModel = async (
    request: Request,
    response: Response,
  ): Promise<{ model: unknown; source: "header" | "cookie" } | null> => {
    const accessName = options.cookie ?? authConfig.cookie.name();
    const refreshName = options.refreshCookie ?? authConfig.cookie.refreshName();
    // A present Authorization header wins and never falls back to the cookie.
    const headerWins = useHeader && Boolean(request.authorizationValue);

    if (!headerWins && !useCookie) return null;

    // Cheap guest path: nothing to decode, so nothing is marked auth-derived.
    if (!headerWins && !request.cookie(accessName) && !request.cookie(refreshName)) return null;

    const allowedTypes = resolveUserTypes(options.userTypes);
    const renewalUserType = allowedTypes.length === 1 ? allowedTypes[0] : undefined;
    const canRenew = !headerWins && renew && Boolean(renewalUserType);

    const model = await resolveRequestUser(request, response, {
      tokenFrom: headerWins ? "header" : `cookie:${accessName}`,
      refreshCredential: canRenew ? `cookie:${refreshName}` : undefined,
      overlapMs: options.overlapMs,
      maxAgeMs: resolveMaxAgeMs(options.maxAge),
      allowedTypes,
      renewalUserType,
    });

    if (!model) return null;

    request.locals.user = model;

    return { model, source: headerWins ? "header" : "cookie" };
  };

  return resolveModel;
}

/**
 * Session resolver for pages: cookie-or-header credential, reactive renewal,
 * one resolution per request. Plug it into `web.session`.
 *
 * @example
 * export default { session: pageSession({ project: (user: User) => userResource(user) }) };
 */
export function pageSession<TModel = any, TUser = unknown>(
  options: PageSessionOptions<TModel, TUser>,
): PageSessionResolver<TModel, TUser> {
  if (typeof options?.project !== "function") {
    throw new Error(
      "pageSession requires a `project(model)` function: a model never crosses the wire by default.",
    );
  }

  const resolveModel = createModelResolver(options);
  const projections = new WeakMap<object, Promise<unknown>>();

  return {
    async resolve(request, response) {
      const resolved = await resolveModel(request, response);

      if (!resolved) return null;

      const model = resolved.model as TModel;
      let projected = projections.get(request as object);

      if (!projected) {
        projected = Promise.resolve(options.project(model));
        projections.set(request as object, projected);
      }

      return { model, user: (await projected) as TUser };
    },
  };
}

/**
 * Middleware for cookie API routes over the same resolver as `pageSession`.
 * A cookie-authenticated unsafe request must pass the Origin/Referer check
 * (renewal can mint cookies, so it runs even when the access cookie is gone).
 * Guests get a 401 unless `optional`. The user lands on `request.locals.user`.
 */
export function sessionMiddleware(options: SessionMiddlewareOptions = {}): Middleware {
  const resolveModel = createModelResolver(options);
  const sources = options.sources?.length ? options.sources : ["cookie", "header"];

  return async ({ request, response }) => {
    const headerWins = sources.includes("header") && Boolean(request.authorizationValue);

    if (!headerWins && requiresCsrfOriginCheck("cookie:x", request.method)) {
      const accessName = options.cookie ?? authConfig.cookie.name();
      const refreshName = options.refreshCookie ?? authConfig.cookie.refreshName();

      if (request.cookie(accessName) || request.cookie(refreshName)) {
        try {
          assertCsrfOriginAllowed(request);
        } catch (error) {
          if (!(error instanceof CsrfOriginMismatchError)) throw error;

          log.error("http", "auth", error);

          return response.forbidden({
            error: t("auth.errors.csrfOriginMismatch"),
            errorCode: AuthErrorCodes.CsrfOriginMismatch,
          });
        }
      }
    }

    const resolved = await resolveModel(request, response);

    if (resolved || options.optional) return;

    return response.unauthorized({
      error: t("auth.errors.unauthorized"),
      errorCode: AuthErrorCodes.Unauthorized,
    });
  };
}
