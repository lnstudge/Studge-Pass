// Validates docs/preview/status.json against status.schema.json.
// Used by `pnpm build` (prebuild) and by the update script after every write.
//
// Run directly:  node scripts/validate-status.mjs
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const schemaPath = path.join(packageRoot, "status.schema.json");

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Validates a status object. Throws a readable error on the first problem.
 * `root` is the repository root used to resolve screenshot paths.
 */
export function validateData(data, root = repoRoot) {
  const schema = readJson(schemaPath);
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  if (!validate(data)) {
    const details = (validate.errors ?? [])
      .map((error) => `  - ${error.instancePath || "/"} ${error.message ?? "invalid"}`)
      .join("\n");
    throw new Error(`status.json does not match status.schema.json:\n${details}`);
  }

  // A gallery entry must point at a file that exists, so the page cannot claim
  // a screenshot that was never taken.
  for (const shot of data.screenshots) {
    const file = path.join(root, "docs", shot.path);
    if (!existsSync(file)) {
      throw new Error(`screenshot listed in status.json is missing: docs/${shot.path}`);
    }
  }

  return data;
}

export function validateStatusFile(root = repoRoot) {
  const statusPath = path.join(root, "docs", "preview", "status.json");
  return validateData(readJson(statusPath), root);
}

const invokedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    const data = validateStatusFile();
    console.log(
      `status.json OK — phase ${data.phase.id}, ${data.steps.length} steps, ` +
        `${data.commits.length} commits, ${data.screenshots.length} screenshots`
    );
  } catch (error) {
    console.error(`status validation failed: ${error.message}`);
    process.exit(1);
  }
}
