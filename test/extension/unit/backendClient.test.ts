/**
 * BackendClient against the real Python backend (no VS Code needed).
 * tshark-dependent tests are skipped when tshark is not installed.
 */
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  BackendClient,
  ErrorCodes,
  Progress,
  MIN_PYTHON,
  RpcError,
  findPython,
  pythonCandidates,
  uvCandidates,
} from "../../../src/backendClient";

import { FIXTURES, HAVE_TSHARK, makeClient, startIsolated, testPython } from "./backendTesting";

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

suite("BackendClient", function () {
  this.timeout(30_000);
  let client: BackendClient;

  setup(() => {
    client = makeClient();
    startIsolated(client);
  });

  teardown(async () => {
    await client.dispose();
  });

  test("findPython reports a missing interpreter", () => {
    const res = findPython("/definitely/not/python");
    assert.ok("error" in res);
    assert.match(res.error, /No Python 3\.12\+ interpreter found/);
  });

  test("Python candidates: versioned names newest first, then generic; a set path alone", () => {
    assert.deepEqual(MIN_PYTHON, [3, 12]);
    assert.deepEqual(pythonCandidates(undefined, "linux"), [
      ["python3.14"],
      ["python3.13"],
      ["python3.12"],
      ["python3"],
      ["python"],
    ]);
    assert.deepEqual(pythonCandidates(undefined, "win32"), [
      ["py", "-3.14"],
      ["py", "-3.13"],
      ["py", "-3.12"],
      ["py", "-3"],
      ["python"],
      ["python3"],
    ]);
    assert.deepEqual(pythonCandidates("/opt/py/bin/python3", "linux"), [["/opt/py/bin/python3"]]);
  });

  test("without a Python on PATH, the one uv knows is used (a desktop-launched VS Code)", function () {
    const python = testPython();
    if (process.platform === "win32" || !python) {
      this.skip(); // (a shell script stands in for uv)
    }
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-uv-"));
    const emptyPath = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-path-"));
    const saved = { HOME: process.env.HOME, PATH: process.env.PATH };
    try {
      const bin = path.join(home, ".local", "bin");
      fs.mkdirSync(bin, { recursive: true });
      const uv = path.join(bin, "uv");
      const script = (found: string) =>
        `#!/bin/sh\n[ "$1" = "--version" ] && { echo "uv 0.9.0"; exit 0; }\n` +
        `[ "$1 $2" = "python find" ] && ${found}\nexit 2\n`;
      fs.writeFileSync(uv, script(`{ echo "${python}"; exit 0; }`), { mode: 0o755 });
      process.env.HOME = home;
      process.env.PATH = emptyPath;
      const found = findPython(undefined);
      assert.ok("python" in found, JSON.stringify(found));
      assert.deepEqual(found.python, [python]);
      // uv without a recent enough Python: the error says it was asked too.
      fs.writeFileSync(uv, script("exit 2"), { mode: 0o755 });
      const missing = findPython(undefined);
      assert.ok("error" in missing);
      assert.match(missing.error, /uv python find/);
    } finally {
      process.env.HOME = saved.HOME;
      process.env.PATH = saved.PATH;
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(emptyPath, { recursive: true, force: true });
    }
  });

  test("uv is looked for on PATH and in its usual folders", () => {
    assert.deepEqual(uvCandidates("linux", "/home/u"), [
      "uv",
      "/home/u/.local/bin/uv",
      "/home/u/.cargo/bin/uv",
    ]);
    assert.deepEqual(uvCandidates("win32", "C:\\Users\\u"), [
      "uv",
      "C:\\Users\\u\\.local\\bin\\uv.exe",
      "C:\\Users\\u\\.cargo\\bin\\uv.exe",
    ]);
  });

  test("unknown methods reject with MethodNotFound", async () => {
    await assert.rejects(
      client.request("nope"),
      (err: RpcError) => err.code === ErrorCodes.MethodNotFound,
    );
  });

  test("requests before start / after stop reject", async () => {
    await client.stop();
    await assert.rejects(
      client.request("ping"),
      (err: RpcError) => err.code === ErrorCodes.BackendExited,
    );
  });

  test("stop terminates the process", async () => {
    const pid = client.pid;
    assert.ok(pid);
    assert.deepEqual(await client.request("ping"), { pong: true });
    await client.stop();
    assert.equal(isAlive(pid), false);
  });

  test("unexpected exit rejects pending requests and fires onExit", async () => {
    const exited = new Promise<boolean>((resolve) => client.onExit((e) => resolve(e.expected)));
    const pending = client.request("ping");
    await pending;
    process.kill(client.pid as number, "SIGKILL");
    assert.equal(await exited, false);
    assert.equal(client.running, false);
  });

  (HAVE_TSHARK ? test : test.skip)("open, filter, page and detail over stdio", async () => {
    const init = await client.request<{ version: string }>("initialize", {});
    assert.match(init.version, /TShark/);
    const progress: Progress[] = [];
    const info = await client.request<{ frames: number }>(
      "open",
      { path: path.join(FIXTURES, "http.pcap") },
      { timeoutMs: 0, onProgress: (p) => progress.push(p) },
    );
    assert.equal(info.frames, 11);
    assert.ok(progress.some((p) => p.phase === "indexing"));
    const filtered = await client.request<{ matchCount: number }>("set_filter", { expr: "http" });
    assert.equal(filtered.matchCount, 2);
    const page = await client.request<{ rows: { number: number }[] }>("list_packets", {
      offset: 0,
      limit: 10,
    });
    assert.deepEqual(
      page.rows.map((r) => r.number),
      [4, 7],
    );
    const detail = await client.request<{ tree: { name?: string }[]; sources: unknown[] }>(
      "packet_detail",
      { number: 7 },
    );
    assert.ok(detail.tree.some((n) => n.name === "http"));
    assert.equal(detail.sources.length, 2);
    await assert.rejects(
      client.request("set_filter", { expr: "http.host ==" }),
      (err: RpcError) => err.code === ErrorCodes.InvalidFilter,
    );
  });

  (HAVE_TSHARK ? test : test.skip)("cancellation via token", async () => {
    await client.request("initialize", {});
    let cancel: () => void = () => undefined;
    const token = {
      isCancellationRequested: false,
      onCancellationRequested(cb: () => void) {
        cancel = () => {
          token.isCancellationRequested = true;
          cb();
        };
        return { dispose() {} };
      },
    };
    const p = client.request(
      "open",
      { path: path.join(FIXTURES, "mixed.pcapng") },
      { timeoutMs: 0, cancellation: token },
    );
    cancel();
    // Either the open finished before the cancel landed, or it was cancelled.
    await p.then(
      () => undefined,
      (err: RpcError) => assert.equal(err.code, ErrorCodes.RequestCancelled),
    );
    assert.deepEqual(await client.request("ping"), { pong: true });
  });
});
