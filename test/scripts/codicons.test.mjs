import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FILES, VENDOR, packagePath } from "../../scripts/sync-codicons.mjs";

suite("vendored codicons", () => {
  for (const name of Object.keys(FILES)) {
    test(`${name} matches the installed @vscode/codicons (pnpm run codicons)`, () => {
      assert.ok(
        readFileSync(join(VENDOR, name)).equals(readFileSync(packagePath(name))),
        `src/webview/codicons/${name} differs: run pnpm run codicons`,
      );
    });
  }
});
