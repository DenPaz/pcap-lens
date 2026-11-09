// Settings for `ncu -u` (npm-check-updates, e.g. `pnpm dlx npm-check-updates -u`).
module.exports = {
  // Respect peer ranges: typescript-eslint caps the TypeScript version.
  peer: true,
  // Must not exceed engines.vscode (vsce refuses to package); raise both together.
  reject: ["@types/vscode"],
  // Match the Node that VS Code 1.90 runs extensions on (Node 20).
  // mocha-smoke (mocha 11) runs the smoke suite inside VS Code 1.90's Node
  // 20.9, which mocha 12 can't load in.
  target: (name) => (name === "@types/node" || name === "mocha-smoke" ? "minor" : "latest"),
};
