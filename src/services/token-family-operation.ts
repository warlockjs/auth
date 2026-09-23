import { databaseTransactionContext, transaction } from "@warlock.js/cascade";
import { AsyncLocalStorage } from "node:async_hooks";
import { AuthTokenFamily } from "../models/auth-token-family";

const operationEffects = new AsyncLocalStorage<Array<() => void>>();

/** Defer events until this coordinator's owned transaction commits. */
export function afterTokenFamilyOperation(effect: () => void): void {
  const effects = operationEffects.getStore();
  if (effects) effects.push(effect);
  else effect();
}

/** A CAS miss is retried only when this helper owns the transaction boundary. */
class TokenFamilyConflictError extends Error {
  public constructor() {
    super("Token family changed concurrently");
    this.name = "TokenFamilyConflictError";
  }
}

/** A missing or revoked family cannot become usable through a retry. */
export class TokenFamilyUnavailableError extends Error {
  public constructor() {
    super("Token family is unavailable");
    this.name = "TokenFamilyUnavailableError";
  }
}

type TransactionError = {
  code?: unknown;
  hasErrorLabel?: (label: string) => boolean;
};

const MAX_OWNED_TRANSACTION_ATTEMPTS = 3;

function isRetryableTransactionError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;

  const transactionError = error as Error & TransactionError;

  return (
    transactionError.code === "40001" ||
    transactionError.hasErrorLabel?.("TransientTransactionError") === true
  );
}

/**
 * Perform one family state transition in a transaction and advance its durable
 * revision with a conditional update. An existing Cascade transaction is
 * joined, never retried here: PostgreSQL marks an outer transaction aborted on
 * a serialization error, so only that transaction's owner can safely retry.
 *
 * The finite internal cap prevents request handlers from retrying forever.
 * Transaction setup failures are deliberately propagated; this auth boundary
 * has no non-transactional fallback.
 */
export async function runTokenFamilyOperation<T>(
  familyId: string,
  operation: (family: AuthTokenFamily) => Promise<T>,
): Promise<T> {
  const joinsExistingTransaction = databaseTransactionContext.hasActiveTransaction();
  const attempts = joinsExistingTransaction ? 1 : MAX_OWNED_TRANSACTION_ATTEMPTS;
  let lastError: unknown;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const parentEffects = operationEffects.getStore();
    const effects: Array<() => void> = [];
    let result: T;
    try {
      result = await operationEffects.run(effects, () =>
        transaction(
          async () => {
            const family = await AuthTokenFamily.findByFamilyId(familyId);

            if (!family || family.isRevoked) {
              throw new TokenFamilyUnavailableError();
            }

            const revision = family.get<number>("revision");
            const advanced = await AuthTokenFamily.advanceRevision(familyId, revision);

            if (advanced !== 1) {
              throw new TokenFamilyConflictError();
            }

            return operation(family);
          },
          { isolationLevel: "SERIALIZABLE" },
        ),
      );
    } catch (error) {
      lastError = error;

      if (
        joinsExistingTransaction ||
        (!isRetryableTransactionError(error) && !(error instanceof TokenFamilyConflictError))
      ) {
        throw error;
      }
      continue;
    }

    // Listener failures must never retry a transaction that already committed.
    // Nested family operations join their parent's queue. An app-owned outer
    // transaction has no Cascade commit hook, so its existing event timing is
    // retained; its owner remains responsible for external side effects.
    if (parentEffects) parentEffects.push(...effects);
    else for (const effect of effects) effect();
    return result;
  }

  throw lastError;
}

export { TokenFamilyConflictError };
