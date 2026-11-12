import * as assert from "node:assert/strict";
import * as path from "node:path";
import { byFileName, captureCandidates, insideAny, toolsMayRead } from "../../../src/aiCapturePath";

const root = path.resolve("/work");
const at = (...parts: string[]) => path.join(root, ...parts);

suite("AI tools: the capture a capture argument names", () => {
  test("candidates: absolute paths, file: URIs, else relative to each folder", () => {
    assert.deepEqual(captureCandidates(at("a.pcap"), [at("x")]), [at("a.pcap")]);
    assert.deepEqual(captureCandidates(`"${at("a.pcap")}"`, []), [at("a.pcap")], "quotes go");
    assert.deepEqual(captureCandidates("caps/a.pcap", [at("x"), at("y"), at("x")]), [
      at("x", "caps", "a.pcap"),
      at("y", "caps", "a.pcap"),
    ]);
    if (process.platform !== "win32") {
      assert.deepEqual(captureCandidates("file:///work/my%20caps/a.pcap", []), [
        "/work/my caps/a.pcap",
      ]);
    }
    assert.deepEqual(captureCandidates("  ", [at("x")]), []);
    assert.deepEqual(captureCandidates("file://%zz", []), [], "a broken URI names nothing");
  });

  test("by file name among known captures", () => {
    const known = [at("a", "dns.pcap"), at("b", "http.pcap"), at("a", "dns.pcap")];
    assert.deepEqual(byFileName("dns.pcap", known), [at("a", "dns.pcap")]);
    assert.deepEqual(byFileName("some/where/http.pcap", known), [at("b", "http.pcap")]);
    assert.deepEqual(byFileName("x.pcap", known), []);
  });

  test("the tools read only the workspace, the viewer's captures and Recent Captures", () => {
    const places = {
      folders: [at("proj")],
      open: [at("elsewhere", "open.pcap")],
      recent: [at("downloads", "recent.pcap")],
    };
    assert.ok(toolsMayRead(at("proj", "caps", "a.pcap"), places));
    assert.ok(toolsMayRead(at("elsewhere", "open.pcap"), places));
    assert.ok(toolsMayRead(at("downloads", "recent.pcap"), places));
    assert.ok(!toolsMayRead(at("downloads", "other.pcap"), places));
    assert.ok(!toolsMayRead(at("proj-other", "a.pcap"), places), "a sibling isn't inside");
    assert.ok(!toolsMayRead(path.resolve("/etc/passwd"), places));
    assert.ok(insideAny(at("proj"), [at("proj")]));
    assert.ok(!insideAny(at("proj", "..", "x"), [at("proj")]));
  });
});
