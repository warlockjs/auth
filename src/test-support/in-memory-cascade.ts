/**
 * Spec-only stand-in for `@warlock.js/cascade`: an in-memory table store
 * behind the `Model` statics auth's models use. Every store call yields
 * first, so concurrent flows genuinely interleave; `atomic` then matches and
 * writes in one synchronous step — the compare-and-set guarantee a
 * conditional UPDATE gives. Filters support equality, `null` (= null or
 * absent) and `{ $lt }`; updates support `$set` and `$inc`.
 */

export type Row = Record<string, unknown>;

type Filter = Record<string, unknown>;

type AtomicOperations = { $set?: Row; $inc?: Record<string, number> };

export const tables = new Map<string, Row[]>();

let nextId = 0;
let sequence = 0;

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

function rowsOf(table: string): Row[] {
  let rows = tables.get(table);

  if (!rows) {
    rows = [];
    tables.set(table, rows);
  }

  return rows;
}

function matches(row: Row, filter: Filter): boolean {
  return Object.entries(filter).every(([key, expected]) => {
    const actual = row[key];

    if (expected === null) return actual === null || actual === undefined;

    if (typeof expected === "object" && expected !== null && "$lt" in expected) {
      return (actual as number) < (expected as { $lt: number }).$lt;
    }

    return actual === expected;
  });
}

/** Clear every table (call in `beforeEach`). */
export function resetTables(): void {
  tables.clear();
}

type ModelClass = { table: string; new (data: Row): InMemoryModel };

export class InMemoryModel {
  public static table = "";

  public data: Row;

  public constructor(data: Row) {
    this.data = data;
  }

  public get id() {
    return this.data.id;
  }

  public get(key: string) {
    return this.data[key];
  }

  public string(key: string) {
    return this.data[key] as string | undefined;
  }

  public merge(values: Row) {
    Object.assign(this.data, values);

    return this;
  }

  public async save() {
    await tick();

    return this;
  }

  public static async create(this: ModelClass, data: Row) {
    await tick();
    const row: Row = { id: ++nextId, created_at: ++sequence, ...data };
    rowsOf(this.table).push(row);

    return new this(row);
  }

  public static async first(this: ModelClass, filter: Filter) {
    await tick();
    const row = rowsOf(this.table).find((candidate) => matches(candidate, filter));

    return row ? new this(row) : null;
  }

  public static async find(this: ModelClass, id: unknown) {
    await tick();
    const row = rowsOf(this.table).find((candidate) => candidate.id === id);

    return row ? new this(row) : null;
  }

  public static query(this: ModelClass) {
    const ModelRef = this;
    let filter: Filter = {};
    let order: [string, "asc" | "desc"] | undefined;

    const select = () => {
      const rows = rowsOf(ModelRef.table).filter((row) => matches(row, filter));

      if (order) {
        const [field, direction] = order;
        rows.sort(
          (a, b) => ((a[field] as number) - (b[field] as number)) * (direction === "desc" ? -1 : 1),
        );
      }

      return rows.map((row) => new ModelRef(row));
    };

    const builder = {
      where(next: Filter) {
        filter = { ...filter, ...next };

        return builder;
      },
      orderBy(field: string, direction: "asc" | "desc" = "asc") {
        order = [field, direction];

        return builder;
      },
      async first() {
        await tick();

        return select()[0] ?? null;
      },
      async get() {
        await tick();

        return select();
      },
    };

    return builder;
  }

  public static async atomic(this: ModelClass, filter: Filter, operations: AtomicOperations) {
    await tick();
    let modified = 0;

    for (const row of rowsOf(this.table).filter((candidate) => matches(candidate, filter))) {
      Object.assign(row, operations.$set ?? {});

      for (const [key, by] of Object.entries(operations.$inc ?? {})) {
        row[key] = ((row[key] as number) ?? 0) + by;
      }

      modified++;
    }

    return modified;
  }
}

/** The module object to return from `vi.mock("@warlock.js/cascade", ...)`. */
export const cascadeModule = {
  Model: InMemoryModel,
  migrate: () => ({}),
};

/** A `v` whose every validator and modifier chains — for `vi.mock("@warlock.js/seal", ...)`. */
export const sealModule = (() => {
  const chain: object = new Proxy(() => chain, {
    get: () => chain,
    apply: () => chain,
  });

  return { v: chain };
})();
