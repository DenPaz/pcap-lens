/**
 * Launches VS Code (downloaded by @vscode/test-electron) with this extension
 * and runs the smoke suite in test/extension/suite. On headless Linux run
 * under xvfb-run. PCAP_VSCODE_VERSION picks the VS Code: a version, or
 * "minimum" for the one `engines.vscode` names (CI runs both that and the
 * latest stable, the default).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { runTests } from "@vscode/test-electron";

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
    await runTests({
      ...(version ? { version } : {}),
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
