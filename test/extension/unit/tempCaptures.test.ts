/** Unsaved captures' files and the per-capture Lua choices (no VS Code needed: stand-ins). */
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type * as vscode from "vscode";
import { initLuaChoices, luaChoiceFor, setLuaChoice } from "../../../src/luaChoice";
import {
  discardTemporaryCapture,
  isTemporaryCapture,
  newTemporaryCapture,
  pruneTemporaryCaptures,
  temporaryCapturesDir,
} from "../../../src/tempCaptures";

const fileUri = (fsPath: string) => ({ scheme: "file", fsPath }) as vscode.Uri;

async function until(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > end) {
      throw new Error("timed out");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

suite("unsaved captures", () => {
  let storage: string;
  let context: vscode.ExtensionContext;

  setup(() => {
    storage = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-storage-"));
    context = { globalStorageUri: fileUri(storage) } as vscode.ExtensionContext;
  });
  teardown(() => fs.rmSync(storage, { recursive: true, force: true }));

  test("a new one is an empty file in a folder of its own, and recognised", async () => {
    const a = await newTemporaryCapture(context, "capture.pcapng");
    const b = await newTemporaryCapture(context, "capture.pcapng");
    assert.notEqual(path.dirname(a), path.dirname(b), "one folder each, same name");
    assert.equal(path.basename(a), "capture.pcapng");
    assert.equal(fs.statSync(a).size, 0);
    assert.ok(isTemporaryCapture(context, fileUri(a)));
    const root = temporaryCapturesDir(context);
    assert.ok(!isTemporaryCapture(context, fileUri(root)), "the folder itself isn't one");
    assert.ok(!isTemporaryCapture(context, fileUri(path.join(root, "..", "x.pcapng"))));
    assert.ok(!isTemporaryCapture(context, fileUri(path.join(os.tmpdir(), "x.pcapng"))));
    assert.ok(!isTemporaryCapture(context, { scheme: "vsls", fsPath: a } as vscode.Uri));
  });

  test("discarding removes its folder, never one outside the captures folder", async () => {
    const file = await newTemporaryCapture(context, "x.pcapng");
    discardTemporaryCapture(context, file, 0);
    await until(() => !fs.existsSync(path.dirname(file)));
    const elsewhere = fs.mkdtempSync(path.join(storage, "other-"));
    fs.writeFileSync(path.join(elsewhere, "keep.pcapng"), "");
    discardTemporaryCapture(context, path.join(elsewhere, "keep.pcapng"), 0);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.ok(fs.existsSync(path.join(elsewhere, "keep.pcapng")));
  });

  test("pruning removes old folders, keeps recent ones and those still open", async () => {
    const old = await newTemporaryCapture(context, "old.pcapng");
    const open = await newTemporaryCapture(context, "open.pcapng");
    const recent = await newTemporaryCapture(context, "recent.pcapng");
    const weekAgo = new Date(Date.now() - 8 * 86_400_000);
    for (const f of [old, open]) {
      fs.utimesSync(path.dirname(f), weekAgo, weekAgo);
    }
    await pruneTemporaryCaptures(context, new Set([open]));
    assert.ok(!fs.existsSync(path.dirname(old)));
    assert.ok(fs.existsSync(open) && fs.existsSync(recent));
    // No captures folder yet: nothing to do, no error.
    fs.rmSync(temporaryCapturesDir(context), { recursive: true });
    await pruneTemporaryCaptures(context, new Set());
  });
});

suite("Lua choices per capture", () => {
  const memento = () => {
    const data = new Map<string, unknown>();
    return {
      get: (key: string) => data.get(key),
      update: async (key: string, value: unknown) => void data.set(key, value),
      data,
    };
  };

  test("chosen scripts per capture path; none chosen = every script", async () => {
    const m = memento();
    initLuaChoices(m as unknown as vscode.Memento);
    const capture = fileUri([os.tmpdir(), "a", "..", "x.pcap"].join(path.sep)); // (not normalised)
    assert.equal(luaChoiceFor(capture), undefined);
    assert.equal(luaChoiceFor(undefined), undefined);
    await setLuaChoice(capture, ["/lua/one.lua"]);
    // The same file however its path is written.
    assert.deepEqual(luaChoiceFor(fileUri(path.join(os.tmpdir(), "x.pcap"))), ["/lua/one.lua"]);
    await setLuaChoice(capture, []);
    assert.deepEqual(luaChoiceFor(capture), [], "none at all is a choice too");
    await setLuaChoice(capture, undefined);
    assert.equal(luaChoiceFor(capture), undefined);
    // Stored data of another shape is ignored.
    m.data.set("pcapViewer.luaChoices", ["not", "an", "object"]);
    assert.equal(luaChoiceFor(capture), undefined);
    m.data.set("pcapViewer.luaChoices", { [path.normalize(capture.fsPath)]: ["/ok.lua", 3] });
    assert.deepEqual(luaChoiceFor(capture), ["/ok.lua"]);
  });

  test("the 500 most recently chosen are kept", async () => {
    initLuaChoices(memento() as unknown as vscode.Memento);
    const uri = (i: number) => fileUri(path.join(os.tmpdir(), `c${i}.pcap`));
    for (let i = 0; i < 502; i++) {
      await setLuaChoice(uri(i), [`/s${i}.lua`]);
    }
    await setLuaChoice(uri(2), ["/again.lua"]); // chosen again: now the most recent
    await setLuaChoice(uri(502), []);
    assert.equal(luaChoiceFor(uri(0)), undefined);
    assert.equal(luaChoiceFor(uri(1)), undefined);
    assert.equal(luaChoiceFor(uri(3)), undefined, "the oldest left after uri(2) moved up");
    assert.deepEqual(luaChoiceFor(uri(2)), ["/again.lua"]);
    assert.deepEqual(luaChoiceFor(uri(4)), ["/s4.lua"]);
    assert.deepEqual(luaChoiceFor(uri(502)), []);
  });
});
