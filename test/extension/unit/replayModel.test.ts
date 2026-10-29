import * as assert from "node:assert/strict";
import * as path from "node:path";
import {
  DEFAULT_OPTIONS,
  MAX_PRESETS,
  MAX_REMEMBERED,
  ReplaySetup,
  destinationProblem,
  isCaptureFileName,
  isTargetKey,
  normalizeDestinations,
  normalizeOptions,
  normalizePresets,
  parseSetup,
  rememberDestinations,
  setupToJson,
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
      ...DEFAULT_OPTIONS,
      speed: 0,
      loops: 3,
      scope: "filter",
    });
    assert.deepEqual(
      normalizeOptions({ loops: 0, order: "merged", jitter: 20, loss: 2.5 }),
      { ...DEFAULT_OPTIONS, loops: 0, order: "merged", jitter: 20, loss: 2.5 },
      "loops 0: until stopped",
    );
    assert.deepEqual(
      normalizeOptions({ speed: -1, loops: 1.5, scope: "x", order: "y", jitter: -1, loss: 101 }),
      DEFAULT_OPTIONS,
    );
    assert.deepEqual(normalizeOptions({ speed: 5000, loops: 1001, jitter: NaN }), DEFAULT_OPTIONS);
    assert.deepEqual(normalizeOptions(null), DEFAULT_OPTIONS);
  });

  test("capture file names (Add Folder…)", () => {
    for (const name of [
      "a.pcap",
      "B.PCAPNG",
      "c.cap",
      "d.pcap.gz",
      "e.pcapng.zst",
      "f.pcap12",
      "g.erf",
    ]) {
      assert.ok(isCaptureFileName(name), name);
    }
    for (const name of ["notes.txt", "a.pcap.txt", "setup.json", "pcap"]) {
      assert.ok(!isCaptureFileName(name), name);
    }
  });

  test("setup files: saved relative to their folder, read back checked", () => {
    const dir = path.resolve("/work/samples");
    const setup: ReplaySetup = {
      includeOpen: false,
      captures: [
        { path: path.join(dir, "ETSI", "llamada_MT.pcap"), enabled: true },
        { path: path.resolve("/elsewhere/other.pcapng"), enabled: false },
      ],
      targets: { "tcp 10.20.0.5:11000": { ip: "127.0.0.1", port: 11000, enabled: true } },
      options: { ...DEFAULT_OPTIONS, loops: 0, order: "merged", jitter: 5, loss: 1 },
    };
    const text = setupToJson(setup, dir);
    const doc = JSON.parse(text);
    assert.equal(doc.format, "pcap-lens-replay");
    assert.equal(doc.captures[0].path, "ETSI/llamada_MT.pcap");
    assert.equal(doc.captures[1].path, "../../elsewhere/other.pcapng");
    const back = parseSetup(text, dir);
    assert.ok("setup" in back);
    assert.deepEqual(back.setup, setup);
    assert.deepEqual(back.problems, []);
    // Another folder holding the same relative layout reads it the same way.
    const moved = parseSetup(text, path.resolve("/copy/samples"));
    assert.ok("setup" in moved);
    assert.equal(moved.setup.captures[0].path, path.resolve("/copy/samples/ETSI/llamada_MT.pcap"));
  });

  test("setup files: what can't be used is named", () => {
    assert.match((parseSetup("{", "/x") as { error: string }).error, /not JSON/);
    assert.match((parseSetup("[]", "/x") as { error: string }).error, /not a replay setup/);
    assert.match(
      (parseSetup(JSON.stringify({ format: "other" }), "/x") as { error: string }).error,
      /not a replay setup/,
    );
    assert.match(
      (
        parseSetup(JSON.stringify({ format: "pcap-lens-replay", version: 9 }), "/x") as {
          error: string;
        }
      ).error,
      /newer PCAP Lens/,
    );
    const parsed = parseSetup(
      JSON.stringify({
        format: "pcap-lens-replay",
        version: 1,
        captures: [{ path: "a.pcap" }, { path: "a.pcap" }, { enabled: true }],
        targets: {
          "tcp 10.0.0.1:80": { ip: "127.0.0.1", port: 8080, enabled: false },
          "tcp 10.0.0.1:81": { ip: "127.0.0.1", port: 0 },
        },
        options: { speed: 2, loss: 500 },
      }),
      path.resolve("/x"),
    );
    assert.ok("setup" in parsed);
    assert.deepEqual(parsed.setup.captures, [{ path: path.resolve("/x/a.pcap"), enabled: true }]);
    assert.deepEqual(parsed.setup.targets, {
      "tcp 10.0.0.1:80": { ip: "127.0.0.1", port: 8080, enabled: false },
    });
    assert.equal(parsed.setup.includeOpen, true);
    assert.deepEqual(parsed.setup.options, { ...DEFAULT_OPTIONS, speed: 2 });
    assert.deepEqual(parsed.problems, [
      "a capture without a path was left out",
      "tcp 10.0.0.1:81: not a recorded target with an IP and port",
    ]);
  });
});
