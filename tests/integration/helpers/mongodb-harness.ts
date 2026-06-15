import { MongoDBContainer, type StartedMongoDBContainer } from "@testcontainers/mongodb";
import { DataSource, dataSourceRegistry, MongoDbDriver } from "@warlock.js/cascade";
import type { Db } from "mongodb";

/**
 * `MongoDBContainer` boots a single-node REPLICA SET — MongoDB needs one for the
 * multi-document transactions cascade's id generator relies on.
 */
const DEFAULT_MONGODB_IMAGE = "mongo:7";
const DEFAULT_DATABASE = "auth_test";

/**
 * A live MongoDB test harness for `@warlock.js/auth`: a running container, a
 * connected cascade `MongoDbDriver` + `DataSource` registered as the default (so
 * the token models resolve to it), and the native `Db` handle for assertions.
 *
 * Built on the PUBLIC `@warlock.js/cascade` surface. Unlike Postgres there is no
 * migration step — Mongo collections are created on first write.
 *
 * @example
 * ```typescript
 * let harness: MongodbHarness;
 *
 * beforeAll(async () => {
 *   harness = await startMongodbHarness();
 * }, 120_000);
 *
 * afterAll(async () => {
 *   await harness.stop();
 * });
 * ```
 */
export type MongodbHarness = {
  /** The started testcontainers MongoDB instance. */
  container: StartedMongoDBContainer;
  /** The connected cascade MongoDB driver. */
  driver: MongoDbDriver;
  /** The registered cascade data source wrapping the driver. */
  dataSource: DataSource;
  /** The native MongoDB database handle, for model-bypassing assertions. */
  db: Db;
  /** Drop the given collections (ignoring "namespace not found") for a clean slate. */
  dropCollections: (...collections: string[]) => Promise<void>;
  /** Disconnect the driver, clear the registry, and stop the container. */
  stop: () => Promise<void>;
};

/**
 * Start a real MongoDB container, connect a cascade data source to it, and
 * register that data source as the default. Always pair it with `stop()` in
 * `afterAll`.
 */
export async function startMongodbHarness(): Promise<MongodbHarness> {
  const container = await new MongoDBContainer(DEFAULT_MONGODB_IMAGE).start();

  const driver = new MongoDbDriver({
    uri: container.getConnectionString(),
    database: DEFAULT_DATABASE,
    logging: false,
    clientOptions: { directConnection: true },
  });

  await driver.connect();

  const dataSource = new DataSource({ name: "mongo-test", driver, isDefault: true });

  dataSourceRegistry.register(dataSource);

  const db = driver.getDatabase();

  const dropCollections = async (...collections: string[]) => {
    for (const collection of collections) {
      await db
        .collection(collection)
        .drop()
        .catch(() => undefined);
    }
  };

  const stop = async () => {
    await driver.disconnect();
    dataSourceRegistry.clear();
    await container.stop();
  };

  return { container, driver, dataSource, db, dropCollections, stop };
}
