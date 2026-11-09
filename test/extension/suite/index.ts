import * as path from "node:path";
import { startCoverage } from "./coverage";

export async function run(): Promise<void> {
  const writeCoverage = await startCoverage();
  // mocha 11 (the `mocha-smoke` alias): mocha 12's CommonJS entry requires
  // ES modules, which VS Code 1.90's Node 20.9 can't (require(esm) came in
  // Node 20.19), and the smoke test also runs on the oldest VS Code supported.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const Mocha = require("mocha-smoke") as typeof import("mocha");
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 60_000 });
  mocha.addFile(path.resolve(__dirname, "smoke.test.js"));
  const failures = await new Promise<number>((resolve) => mocha.run(resolve));
  await writeCoverage?.();
  if (failures) {
    throw new Error(`${failures} test(s) failed`);
  }
}
