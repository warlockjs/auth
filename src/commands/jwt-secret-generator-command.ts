import { command } from "@warlock.js/core";
import { generateJWTSecret } from "../services/generate-jwt-secret";

export function registerJWTSecretGeneratorCommand() {
  return command({
    name: "jwt.generate",
    description: "Generate JWT Secret key in .env file",
    action: generateJWTSecret,
  });
}
