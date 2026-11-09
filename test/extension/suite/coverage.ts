/**
 * Coverage of the extension host code, which only runs inside VS Code (the
 * smoke test). With PCAP_HOST_COVERAGE=<folder>, V8's precise coverage runs
 * while the suite does, and the bundle's share (dist/extension.js) is written
 * there in c8's format; `c8 report --temp-directory <folder>` maps it through
 * the bundle's source map back to src/*.ts. Kept apart from the unit tests'
 * report: the bundle's functions don't line up with tsc's, so a merge
 * miscounts them.
 */
import * as fs from "node:fs";
import * as inspector from "node:inspector";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

interface ScriptCoverage {
  url: string;
  scriptId: string;
  functions: unknown[];
}

/** Starts collecting, if asked; the returned function writes what was collected. */
export async function startCoverage(): Promise<(() => Promise<void>) | undefined> {
  const dir = process.env.PCAP_HOST_COVERAGE;
  if (!dir) {
    return undefined;
  }
  const session = new inspector.Session();
  session.connect();
  const post = <T>(method: string, params: object = {}) =>
    new Promise<T>((resolve, reject) =>
      session.post(method, params, (err, result) => (err ? reject(err) : resolve(result as T))),
    );
  await post("Profiler.enable");
  await post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
  return async () => {
    const { result } = await post<{ result: ScriptCoverage[] }>("Profiler.takePreciseCoverage");
    await post("Profiler.stopPreciseCoverage");
    session.disconnect();
    // Only this extension's bundle: VS Code's built-in extensions have a
    // dist/extension.js of their own (CI's first run counted six).
    const bundle = path.resolve(__dirname, "../../../../dist/extension.js");
    const ours = result
      .filter((s) => samePath(s.url, bundle))
      .map((s) => ({ ...s, url: pathToFileURL(bundle).href }));
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `coverage-host-${process.pid}.json`);
    fs.writeFileSync(file, JSON.stringify({ result: ours }));
    console.log(`Host coverage: ${ours.length} script(s) written to ${file}`);
  };
}

/** Whether a script's URL (a file: URL or a plain path) names `file`. */
function samePath(url: string, file: string): boolean {
  let p: string;
  try {
    p = url.startsWith("file:") ? fileURLToPath(url) : url;
  } catch {
    return false;
  }
  const norm = (x: string) => {
    const r = path.resolve(x);
    return process.platform === "win32" ? r.toLowerCase() : r;
  };
  return norm(p) === norm(file);
}
