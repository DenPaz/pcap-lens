import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SOURCE, TARGET, landPath, worldMapScript } from "../../scripts/world-map.mjs";

suite("vendored world map", () => {
  const topology = JSON.parse(readFileSync(SOURCE, "utf8"));

  test("src/webview/worldmap.js matches the installed world-atlas (pnpm run worldmap)", () => {
    assert.equal(
      readFileSync(TARGET, "utf8"),
      worldMapScript(topology),
      "src/webview/worldmap.js differs: run pnpm run worldmap",
    );
  });

  test("no step crosses the map (rings over the antimeridian are unwrapped)", () => {
    const path = landPath(topology);
    let x = 0;
    let y = 0;
    for (const [, cmd, a, b] of path.matchAll(/([Ml])(-?[\d.]+) (-?[\d.]+)/g)) {
      if (cmd === "l") {
        assert.ok(Math.abs(Number(a)) < 180, `a step of ${a}° at ${x},${y}`);
      }
      [x, y] = cmd === "M" ? [Number(a), Number(b)] : [x + Number(a), y + Number(b)];
      assert.ok(x >= -360 && x <= 720 && y >= -0.05 && y <= 180.05, `${x},${y}`);
    }
    assert.ok(path.split("z").length > 100, "every island and continent");
  });
});
