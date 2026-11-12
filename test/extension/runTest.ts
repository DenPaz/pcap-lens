/**
 * Launches VS Code (downloaded by @vscode/test-electron) with this extension
 * and runs the smoke suite in test/extension/suite. On headless Linux run
 * under xvfb-run. PCAP_VSCODE_VERSION picks the VS Code: a version, or
 * "minimum" for the one `engines.vscode` names (CI runs both that and the
 * latest stable, the default).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { downloadAndUnzipVSCode, runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  const root = path.resolve(__dirname, "../../..");
  const venv = path.join(
    root,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  const python = process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venv) ? venv : "python3");
  const version = vscodeVersion(root, process.env.PCAP_VSCODE_VERSION);
  if (version) {
    console.log(`Smoke test on VS Code ${version}`);
  }
  try {
    const vscodeExecutablePath = await downloadVSCode(root, version);
    await runTests({
      vscodeExecutablePath,
      extensionDevelopmentPath: root,
      extensionTestsPath: path.resolve(__dirname, "suite", "index"),
      // Live capture with a stand-in dumpcap (test/fixtures/fake_dumpcap.py): no capture rights needed.
      extensionTestsEnv: {
        PCAP_VIEWER_DUMPCAP: JSON.stringify([
          python,
          path.join(root, "test", "fixtures", "fake_dumpcap.py"),
        ]),
        FAKE_DUMPCAP_DELAY: "0.05",
        // Coverage of the extension host code (suite/coverage.ts), into c8's folder.
        ...(process.env.PCAP_HOST_COVERAGE
          ? { PCAP_HOST_COVERAGE: path.resolve(process.env.PCAP_HOST_COVERAGE) }
          : {}),
      },
      launchArgs: [
        path.join(root, "test", "fixtures"),
        "--disable-extensions",
        "--disable-workspace-trust",
      ],
    });
  } catch (err) {
    console.error("Extension tests failed:", err);
    process.exit(1);
  }
}

/**
 * Tries for each download, and the idle timeout of each request. The waits
 * between tries grow to a minute, about four minutes in all: VS Code's
 * release list once timed out, and once answered something that wasn't JSON
 * for more than the 30 s three tries had covered (2026-11-12).
 */
const DOWNLOAD_ATTEMPTS = 6;
const RETRY_WAITS_MS = [15_000, 30_000, 60_000, 60_000, 60_000];
const DOWNLOAD_TIMEOUT_MS = 60_000;

/**
 * Downloads (or finds in .vscode-test) the VS Code to test on, retrying: a
 * pinned version is first looked up in VS Code's release list, with no
 * fallback, and that request once took over test-electron's 15 s default
 * and failed CI's oldest-VS-Code job before any test ran.
 */
async function downloadVSCode(root: string, version: string | undefined): Promise<string> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await downloadAndUnzipVSCode({
        ...(version ? { version } : {}),
        extensionDevelopmentPath: root,
        timeout: DOWNLOAD_TIMEOUT_MS,
      });
    } catch (err) {
      if (attempt >= DOWNLOAD_ATTEMPTS) {
        throw err;
      }
      console.warn(`Downloading VS Code failed (attempt ${attempt}), retrying:`, err);
      await new Promise((resolve) =>
        setTimeout(resolve, RETRY_WAITS_MS[Math.min(attempt, RETRY_WAITS_MS.length) - 1]),
      );
    }
  }
}

/** The VS Code to test on: undefined = the latest stable. */
function vscodeVersion(root: string, wanted: string | undefined): string | undefined {
  if (!wanted || wanted === "stable") {
    return undefined;
  }
  if (wanted !== "minimum") {
    return wanted;
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")) as {
    engines: { vscode: string };
  };
  const minimum = /(\d+\.\d+\.\d+)/.exec(pkg.engines.vscode)?.[1];
  if (!minimum) {
    throw new Error(`Can't read a version from engines.vscode "${pkg.engines.vscode}"`);
  }
  return minimum;
}

void main();
