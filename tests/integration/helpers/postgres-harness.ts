import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { DataSource, dataSourceRegistry, PostgresDriver } from "@warlock.js/cascade";

/** Pinned to alpine for a small, fast pull — matches cascade's own harness. */
const DEFAULT_POSTGRES_IMAGE = "postgres:16-alpine";

/** The subset of a driver query result the auth integration specs read. */
export type RawQueryResult<T> = {
  rows: T[];
  rowCount: number | null;
};

/**
 * A live Postgres test harness for `@warlock.js/auth`: a running container, a
 * connected cascade `PostgresDriver` + `DataSource` registered as the default
 * (so the `AccessToken` / `RefreshToken` models resolve to it automatically),
 * plus a raw-SQL escape hatch for assertions that bypass the model layer.
 *
 * Built entirely on the PUBLIC `@warlock.js/cascade` surface — auth consumes the
 * published package, so the harness may not reach into cascade internals.
 *
 * @example
 * ```typescript
 * let harness: PostgresHarness;
 *
 * beforeAll(async () => {
 *   harness = await startPostgresHarness();
 *   const runner = new MigrationRunner({ dataSource: harness.dataSource });
 *   await runner.run(RefreshTokenMigration);
 * }, 120_000);
 *
 * afterAll(async () => {
 *   await harness.stop();
 * });
 * ```
 */
export type PostgresHarness = {
  /** The started testcontainers Postgres instance. */
  container: StartedPostgreSqlContainer;
  /** The connected cascade PostgreSQL driver. */
  driver: PostgresDriver;
  /** The registered cascade data source wrapping the driver. */
  dataSource: DataSource;
  /** Run a raw parameterized SQL statement for direct, model-bypassing assertions. */
  query: <T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ) => Promise<RawQueryResult<T>>;
  /** Disconnect the driver, clear the registry, and stop the container. */
  stop: () => Promise<void>;
};

/**
 * Start a real Postgres container, connect a cascade data source to it, and
 * register that data source as the default. Always pair it with `stop()` in
 * `afterAll`.
 */
export async function startPostgresHarness(): Promise<PostgresHarness> {
  const container = await new PostgreSqlContainer(DEFAULT_POSTGRES_IMAGE)
    .withDatabase("auth_test")
    .withUsername("auth")
    .withPassword("auth")
    .start();

  const driver = new PostgresDriver({
    connectionString: container.getConnectionUri(),
    database: container.getDatabase(),
    logging: false,
  });

  await driver.connect();

  const dataSource = new DataSource({ name: "pg-test", driver, isDefault: true });

  dataSourceRegistry.register(dataSource);

  const query = <T = Record<string, unknown>>(sql: string, params: unknown[] = []) => {
    return driver.query<T>(sql, params) as Promise<RawQueryResult<T>>;
  };

  const stop = async () => {
    await driver.disconnect();
    dataSourceRegistry.clear();
    await container.stop();
  };

  return { container, driver, dataSource, query, stop };
}
