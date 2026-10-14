/**
 * Copies the Codicons font and stylesheet from the @vscode/codicons dev
 * dependency into src/webview/codicons/ (vsce packages with
 * --no-dependencies, so the webviews load a vendored copy).
 *
 *   node scripts/sync-codicons.mjs   (pnpm run codicons; `make update` runs it)
 *
 * test/scripts/codicons.test.mjs fails while the copy differs from the
 * installed package.
 */
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = join(ROOT, "node_modules", "@vscode", "codicons");
export const VENDOR = join(ROOT, "src", "webview", "codicons");

/** Vendored file name → its path inside the package. */
export const FILES = {
  "codicon.css": "dist/codicon.css",
  "codicon.ttf": "dist/codicon.ttf",
  LICENSE: "LICENSE",
  "LICENSE-CODE": "LICENSE-CODE",
};

export function packagePath(name) {
  return join(PACKAGE, FILES[name]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  mkdirSync(VENDOR, { recursive: true });
  for (const name of Object.keys(FILES)) {
    copyFileSync(packagePath(name), join(VENDOR, name));
  }
  console.log(`Copied ${Object.keys(FILES).join(", ")} to ${VENDOR}`);
}
