import { fileExistsAsync, getFileAsync, putFileAsync } from "@mongez/fs";
import { Random } from "@mongez/reinforcements";
import { environment, rootPath } from "@warlock.js/core";
import { log } from "@warlock.js/logger";

export async function generateJWTSecret() {
  let envFile = rootPath(".env");

  log.info("jwt", "generating", "Generating JWT secrets");

  const environmentMode = environment();

  if (!(await fileExistsAsync(envFile))) {
    const envFileType = environmentMode === "production" ? ".env.production" : ".env.development";
    envFile = rootPath(envFileType);
  }

  if (!(await fileExistsAsync(envFile))) {
    log.error("jwt", "error", ".env file not found");
    return;
  }

  let contents = await getFileAsync(envFile);

  const hasJwtSecret = contents.includes("JWT_SECRET");
  const hasJwtRefreshSecret = contents.includes("JWT_REFRESH_SECRET");

  if (hasJwtSecret && hasJwtRefreshSecret) {
    log.warn("jwt", "exists", "JWT secrets already exist in the .env file.");
    return;
  }

  let secretsToAdd = "";

  if (!hasJwtSecret) {
    const jwtSecret = Random.string(32);
    secretsToAdd += `
# JWT Secret
JWT_SECRET=${jwtSecret}
`;
    log.success("jwt", "generated", "JWT_SECRET generated and added to the .env file.");
  } else {
    log.info("jwt", "exists", "JWT_SECRET already exists in the .env file.");
  }

  if (!hasJwtRefreshSecret) {
    const jwtRefreshSecret = Random.string(32);
    secretsToAdd += `
# JWT Refresh Secret
JWT_REFRESH_SECRET=${jwtRefreshSecret}
`;
    log.success("jwt", "generated", "JWT_REFRESH_SECRET generated and added to the .env file.");
  } else {
    log.info("jwt", "exists", "JWT_REFRESH_SECRET already exists in the .env file.");
  }

  if (secretsToAdd) {
    contents += secretsToAdd;
    await putFileAsync(envFile, contents);
  }
}
