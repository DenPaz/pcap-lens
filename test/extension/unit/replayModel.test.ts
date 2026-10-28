import * as assert from "node:assert/strict";
import {
  DEFAULT_OPTIONS,
  MAX_PRESETS,
  MAX_REMEMBERED,
  destinationProblem,
  isTargetKey,
  normalizeDestinations,
  normalizeOptions,
  normalizePresets,
  rememberDestinations,
  withPreset,
  withoutPreset,
} from "../../../src/replayModel";

suite("replay model", () => {
  test("recorded target keys and destinations", () => {
    assert.ok(isTargetKey("tcp 10.20.0.5:11001"));
    assert.ok(isTargetKey("udp [fd00::5]:53"));
    assert.ok(!isTargetKey("sctp 10.0.0.1:1"));
    assert.ok(!isTargetKey("tcp 10.0.0.1"));
    assert.equal(destinationProblem("127.0.0.1", 11000), undefined);
    assert.match(destinationProblem("", 1) ?? "", /IP address/);
    assert.match(destinationProblem("a b", 1) ?? "", /spaces/);
    assert.match(destinationProblem("::1", 0) ?? "", /port/);
    assert.match(destinationProblem("::1", 1.5) ?? "", /port/);
    assert.match(destinationProblem("::1", "80") ?? "", /port/);
  });

  test("destinations keep only well-formed entries", () => {
    assert.deepEqual(
      normalizeDestinations({
        "tcp 10.20.0.5:11001": { ip: " 127.0.0.1 ", port: 11001 },
        "tcp 10.20.0.5:11002": { ip: "127.0.0.1", port: 0 },
        "not a key": { ip: "127.0.0.1", port: 1 },
        "udp 10.20.0.5:53": "127.0.0.1:53",
      }),
      { "tcp 10.20.0.5:11001": { ip: "127.0.0.1", port: 11001 } },
    );
    assert.deepEqual(normalizeDestinations([]), {});
    assert.deepEqual(normalizeDestinations(undefined), {});
  });

  test("presets: named, with mappings, unique, capped", () => {
    const targets = { "tcp 10.20.0.5:11001": { ip: "127.0.0.1", port: 11001 } };
    assert.deepEqual(
      normalizePresets([
        { name: " Local ", targets },
        { name: "Local", targets }, // (a second one of the same name)
        { name: "", targets },
        { name: "Empty", targets: {} },
        { name: "Bad", targets: { "tcp 10.20.0.5:11001": { ip: "", port: 1 } } },
        "x",
      ]),
      [{ name: "Local", targets }],
    );
    const many = Array.from({ length: MAX_PRESETS + 5 }, (_, i) => ({ name: `p${i}`, targets }));
    assert.equal(normalizePresets(many).length, MAX_PRESETS);
    const list = normalizePresets([
      { name: "a", targets },
      { name: "b", targets },
    ]);
    const other = { "udp 10.20.0.5:53": { ip: "127.0.0.1", port: 5353 } };
    assert.deepEqual(
      withPreset(list, { name: "a", targets: other }).map((p) => [p.name, p.targets]),
      [
        ["a", other],
        ["b", targets],
      ],
    );
    assert.deepEqual(
      withPreset(list, { name: "c", targets }).map((p) => p.name),
      ["a", "b", "c"],
    );
    assert.deepEqual(
      withoutPreset(list, "a").map((p) => p.name),
      ["b"],
    );
  });

  test("remembered destinations: the latest first, capped", () => {
    const previous = {
      "tcp 10.20.0.5:11000": { ip: "127.0.0.1", port: 11000 },
      "tcp 10.20.0.5:11001": { ip: "127.0.0.1", port: 11001 },
    };
    const used = { "tcp 10.20.0.5:11001": { ip: "192.168.1.9", port: 9001 } };
    assert.deepEqual(Object.entries(rememberDestinations(previous, used)), [
      ["tcp 10.20.0.5:11001", { ip: "192.168.1.9", port: 9001 }],
      ["tcp 10.20.0.5:11000", { ip: "127.0.0.1", port: 11000 }],
    ]);
    const lots = Object.fromEntries(
      Array.from({ length: MAX_REMEMBERED + 10 }, (_, i) => [
        `tcp 10.0.0.1:${i + 1}`,
        { ip: "127.0.0.1", port: i + 1 },
      ]),
    );
    const kept = rememberDestinations(lots, used);
    assert.equal(Object.keys(kept).length, MAX_REMEMBERED);
    assert.equal(Object.keys(kept)[0], "tcp 10.20.0.5:11001");
  });

  test("options: checked, defaults for the rest", () => {
    assert.deepEqual(normalizeOptions({ speed: 0, loops: 3, scope: "filter" }), {
      speed: 0,
      loops: 3,
      scope: "filter",
    });
    assert.deepEqual(normalizeOptions({ speed: -1, loops: 1.5, scope: "x" }), DEFAULT_OPTIONS);
    assert.deepEqual(normalizeOptions({ speed: 5000, loops: 0 }), DEFAULT_OPTIONS);
    assert.deepEqual(normalizeOptions(null), DEFAULT_OPTIONS);
  });
});
