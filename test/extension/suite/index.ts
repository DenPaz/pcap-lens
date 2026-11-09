import * as path from "node:path";
import { startCoverage } from "./coverage";

export async function run(): Promise<void> {
  const writeCoverage = await startCoverage();
  // mocha 12 is ESM-only; a dynamic import loads it from this CommonJS module
  // in any Node/Electron (require(esm) needs Node >= 22.12).
  const { default: Mocha } = await import("mocha");
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 60_000 });
  mocha.addFile(path.resolve(__dirname, "smoke.test.js"));
  const failures = await new Promise<number>((resolve) => mocha.run(resolve));
  await writeCoverage?.();
  if (failures) {
    throw new Error(`${failures} test(s) failed`);
  }
}
