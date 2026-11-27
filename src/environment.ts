/**
 * The setup check behind the Get Started walkthrough and _PCAP: Check Python
 * and TShark_: is there a Python the backend can run on, and does the backend
 * find tshark? No `vscode` import, so it is unit-tested with fakes.
 */
import * as path from "node:path";
import { MIN_PYTHON } from "./backendClient";

export type PythonStatus =
  { ok: true; version: string; command: string } | { ok: false; error: string };

export type TsharkStatus =
  { ok: true; version: string; path: string } | { ok: false; error: string; skipped?: true };

export interface EnvironmentStatus {
  python: PythonStatus;
  tshark: TsharkStatus;
}

export interface EnvironmentDeps {
  findPython(
    configured: string | undefined,
  ): { python: string[]; version: string } | { error: string };
  /** Start the backend with `python` and run `initialize` (which locates tshark). */
  initialize(
    python: string[],
    tsharkPath: string | undefined,
  ): Promise<{ version: string; tsharkPath: string }>;
}

/** Check Python first: without it the backend can't look for tshark. */
export async function checkEnvironment(
  settings: { pythonPath: string; tsharkPath: string },
  deps: EnvironmentDeps,
): Promise<EnvironmentStatus> {
  const py = deps.findPython(settings.pythonPath || undefined);
  if ("error" in py) {
    return {
      python: { ok: false, error: py.error },
      tshark: {
        ok: false,
        skipped: true,
        error: `TShark is checked once Python ${MIN_PYTHON.join(".")} is found.`,
      },
    };
  }
  const python: PythonStatus = { ok: true, version: py.version, command: py.python.join(" ") };
  try {
    const init = await deps.initialize(py.python, settings.tsharkPath || undefined);
    return {
      python,
      tshark: { ok: true, version: tsharkVersion(init.version), path: init.tsharkPath },
    };
  } catch (err) {
    return {
      python,
      tshark: { ok: false, error: err instanceof Error ? err.message : String(err) },
    };
  }
}

/** "TShark (Wireshark) 4.6.1 (Git v4.6.1 packaged as …)" → "4.6.1". */
export function tsharkVersion(banner: string): string {
  return /(\d+\.\d+\.\d+)/.exec(banner)?.[1] ?? banner.trim();
}

/**
 * One line for a notification. In a remote window (`where`, from
 * `remote.whereLabel`) the tools must be installed there, not locally.
 */
export function environmentSummary(status: EnvironmentStatus, where?: string): string {
  const { python, tshark } = status;
  if (python.ok && tshark.ok) {
    return `Ready${where ? ` in ${where}` : ""}: Python ${python.version} (${python.command}) and TShark ${tshark.version} (${tshark.path}).`;
  }
  const hint = where ? ` PCAP Lens runs in ${where}: install it there.` : "";
  if (!python.ok) {
    return python.error + hint;
  }
  return `Python ${python.version} is fine, but TShark isn't: ${(tshark as { error: string }).error}${hint}`;
}

/** Which setting fixes the first problem. */
export function settingToFix(status: EnvironmentStatus): "pythonPath" | "tsharkPath" | undefined {
  return !status.python.ok ? "pythonPath" : !status.tshark.ok ? "tsharkPath" : undefined;
}

/**
 * The tshark a path picked or typed in _PCAP: Locate TShark…_ names: quotes
 * around it dropped (Windows' Copy as Path adds them), `~` for the home
 * folder, and Wireshark's install folder or macOS's Wireshark.app taken to
 * the tshark inside it. `isDirectory` says whether a path is a folder.
 */
export function tsharkFileFor(
  input: string,
  where: { platform: string; home: string; isDirectory: (p: string) => boolean },
): string {
  const paths = where.platform === "win32" ? path.win32 : path.posix;
  let file = input.trim();
  const quoted = /^(["'])(.*)\1$/.exec(file);
  if (quoted) {
    file = quoted[2].trim();
  }
  if (file === "~" || /^~[\\/]/.test(file)) {
    file = paths.join(where.home, file.slice(1));
  }
  if (where.platform === "darwin" && /\.app\/?$/i.test(file)) {
    return paths.join(file, "Contents", "MacOS", "tshark");
  }
  if (file && where.isDirectory(file)) {
    return paths.join(file, where.platform === "win32" ? "tshark.exe" : "tshark");
  }
  return file;
}

/**
 * Why the program at `file` isn't tshark, from its `--version` line (picking
 * Wireshark itself, or dumpcap beside it, is easy), or undefined when it is.
 */
export function notTsharkReason(file: string, banner: string): string | undefined {
  if (/\btshark\b/i.test(banner)) {
    return undefined;
  }
  const exe = /\.exe$/i.test(file) ? "tshark.exe" : "tshark";
  return `${file} isn't TShark (it says "${banner.trim()}"): pick ${exe}, which Wireshark installs in the same folder.`;
}
