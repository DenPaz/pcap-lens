/**
 * Starting the real Python backend in the unit tests (backendClient.test.ts,
 * aiToolReports.test.ts): the uv .venv's interpreter and an empty home.
 */
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { BackendClient, findPython } from "../../../src/backendClient";

export const ROOT = path.resolve(__dirname, "../../../..");
export const FIXTURES = path.join(ROOT, "test", "fixtures");
export const HAVE_TSHARK = spawnSync("tshark", ["--version"]).status === 0;

export const logs: string[] = [];
const logger = {
  info: (m: string) => logs.push(m),
  warn: (m: string) => logs.push(m),
  error: (m: string) => logs.push(m),
};

/** PCAP_VIEWER_PYTHON, else the uv-managed .venv interpreter (Python 3.14 after `uv sync`; CI also runs it on 3.12). */
export function testPython(): string | undefined {
  const venv = path.join(
    ROOT,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  return process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venv) ? venv : undefined);
}

export function makeClient(): BackendClient {
  const py = findPython(testPython());
  if ("error" in py) {
    throw new Error(py.error);
  }
  return new BackendClient({
    python: py.python,
    backendDir: path.join(ROOT, "backend"),
    logger,
    defaultTimeoutMs: 30_000,
  });
}

/**
 * Start the backend with an empty home (as test/backend/conftest.py runs
 * pytest and test/webview/harness.js the e2e backend): the developer's own
 * Wireshark setup (personal plugins, Decode As, preferences) must not change
 * what the tests see. Only the spawn sees the swap.
 */
const ISOLATED_ENV = [
  "HOME",
  "APPDATA",
  "XDG_CONFIG_HOME",
  "WIRESHARK_CONFIG_DIR",
  "WIRESHARK_PLUGIN_DIR",
];
let isolatedHome: string | undefined;
export function startIsolated(client: BackendClient): void {
  if (!isolatedHome) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "pcapviewer-home-"));
    process.on("exit", () => fs.rmSync(home, { recursive: true, force: true }));
    isolatedHome = home;
  }
  const saved = ISOLATED_ENV.map((name) => [name, process.env[name]] as const);
  for (const name of ISOLATED_ENV) {
    delete process.env[name];
  }
  Object.assign(process.env, {
    HOME: isolatedHome,
    APPDATA: isolatedHome, // Windows: %APPDATA%\Wireshark
    XDG_CONFIG_HOME: path.join(isolatedHome, ".config"),
  });
  try {
    client.start(); // (spawn copies the environment now)
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}
