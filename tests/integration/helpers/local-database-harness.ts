import {
  DataSource,
  dataSourceRegistry,
  MigrationRunner,
  MongoDbDriver,
  PostgresDriver,
} from "@warlock.js/cascade";

/**
 * Harnesses for database servers this process did NOT start — for machines
 * with a local `mongod` / Postgres but no Docker. Mirrors cascade's
 * `local-mongodb-harness.ts` / `local-postgres-harness.ts`:
 *
 * - connection settings come ONLY from the environment (`LOCAL_MONGO_*`,
 *   `LOCAL_PG_*`); with none set, the suites skip instead of failing;
 * - they touch one nominated database and only the tables they are handed;
 * - teardown disconnects, never stops the server.
 *
 * Built on the PUBLIC `@warlock.js/cascade` surface, like the container harnesses.
 */
export type LocalDatabaseHarness = {
  readonly label: "mongodb" | "postgres";
  readonly dataSource: DataSource;
  /** Every row/document of a table, as plain records. */
  readonly rows: (table: string) => Promise<Record<string, unknown>[]>;
  /** Drop the tables (if present) and run the migrations up, in order. */
  readonly migrateFresh: (tables: string[], migrations: unknown[]) => Promise<void>;
  /** Empty the tables, keeping their indexes. */
  readonly truncate: (tables: string[]) => Promise<void>;
  /** Disconnect and clear the registry. Does NOT stop the server. */
  readonly stop: () => Promise<void>;
};

/** Whether `LOCAL_MONGO_URI` + `LOCAL_MONGO_DATABASE` name a server to use. */
export function hasLocalMongodb(): boolean {
  return Boolean(process.env.LOCAL_MONGO_URI && process.env.LOCAL_MONGO_DATABASE);
}

/** Whether `LOCAL_PG_DATABASE` + `LOCAL_PG_USER` name a server to use. */
export function hasLocalPostgres(): boolean {
  return Boolean(process.env.LOCAL_PG_DATABASE && process.env.LOCAL_PG_USER);
}

function requireEnvironmentValue(key: string): string {
  const value = process.env[key];

  if (!value) {
    throw new Error(`${key} is not set. The local database suite refuses to guess a target.`);
  }

  return value;
}

async function runMigrations(dataSource: DataSource, migrations: unknown[]): Promise<void> {
  const runner = new MigrationRunner({ dataSource, verbose: false });

  for (const migration of migrations) {
    await runner.run(migration as never);
  }
}

/** Connect to `LOCAL_MONGO_URI` / `LOCAL_MONGO_DATABASE` and register it as the default source. */
export async function startLocalMongodb(): Promise<LocalDatabaseHarness> {
  const driver = new MongoDbDriver({
    uri: requireEnvironmentValue("LOCAL_MONGO_URI"),
    database: requireEnvironmentValue("LOCAL_MONGO_DATABASE"),
    logging: false,
    clientOptions: { directConnection: true },
  });

  await driver.connect();

  const dataSource = new DataSource({ name: "local-mongo-auth", driver, isDefault: true });

  dataSourceRegistry.register(dataSource);

  const db = driver.getDatabase();

  return {
    label: "mongodb",
    dataSource,
    rows: async (table) =>
      (await db.collection(table).find({}).toArray()) as Record<string, unknown>[],
    migrateFresh: async (tables, migrations) => {
      for (const table of tables) {
        await db
          .collection(table)
          .drop()
          .catch(() => undefined);
      }

      await runMigrations(dataSource, migrations);
    },
    truncate: async (tables) => {
      for (const table of tables) {
        await db.collection(table).deleteMany({});
      }
    },
    stop: async () => {
      await driver.disconnect();
      dataSourceRegistry.clear();
    },
  };
}

/** Connect to the `LOCAL_PG_*` database and register it as the default source. */
export async function startLocalPostgres(): Promise<LocalDatabaseHarness> {
  const database = requireEnvironmentValue("LOCAL_PG_DATABASE");
  const user = requireEnvironmentValue("LOCAL_PG_USER");
  const password = requireEnvironmentValue("LOCAL_PG_PASSWORD");
  const host = process.env.LOCAL_PG_HOST ?? "127.0.0.1";
  const port = process.env.LOCAL_PG_PORT ?? "5432";

  const driver = new PostgresDriver({
    connectionString: `postgres://${user}:${password}@${host}:${port}/${database}`,
    database,
    logging: false,
  });

  await driver.connect();

  const current = await driver.query<{ current_database: string }>("SELECT current_database()");

  if (current.rows[0]?.current_database !== database) {
    await driver.disconnect();
    throw new Error(`Expected to connect to "${database}".`);
  }

  // UUID keys app-wide, so `foreignId("user_id")` in the auth migrations is a
  // uuid column matching the test users' `primaryUuid()`.
  const dataSource = new DataSource({
    name: "local-pg-auth",
    driver,
    isDefault: true,
    migrationDefaults: { primaryKey: "uuid" },
  });

  dataSourceRegistry.register(dataSource);

  return {
    label: "postgres",
    dataSource,
    rows: async (table) =>
      (await driver.query<Record<string, unknown>>(`SELECT * FROM "${table}"`)).rows,
    migrateFresh: async (tables, migrations) => {
      for (const table of tables) {
        await driver.query(`DROP TABLE IF EXISTS "${table}" CASCADE`);
      }

      await runMigrations(dataSource, migrations);
    },
    truncate: async (tables) => {
      await driver.query(`TRUNCATE TABLE ${tables.map((table) => `"${table}"`).join(", ")}`);
    },
    stop: async () => {
      await driver.disconnect();
      dataSourceRegistry.clear();
    },
  };
}
