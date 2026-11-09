// Prints `version=<latest stable VS Code>` for CI's cache key of the VS Code
// the smoke test downloads (@vscode/test-electron asks the same API), or
// `version=unknown` when the API doesn't answer: the download then just
// isn't cached.
const API = "https://update.code.visualstudio.com/api/releases/stable";

async function latest() {
  try {
    const response = await fetch(API, { signal: AbortSignal.timeout(15_000) });
    const versions = response.ok ? await response.json() : [];
    const first = Array.isArray(versions) ? versions[0] : undefined;
    return typeof first === "string" && /^\d+\.\d+\.\d+$/.test(first) ? first : "unknown";
  } catch {
    return "unknown";
  }
}

console.log(`version=${await latest()}`);
