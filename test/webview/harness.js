/**
 * Shared scaffolding for the Chromium end-to-end tests: serves src/webview
 * over HTTP (so the page CSP can allow it as `cspSource`), renders the editor
 * and panel pages exactly like the extension does, stubs acquireVsCodeApi,
 * and starts the real Python backend.
 */
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../..");
const WEBVIEW = path.join(ROOT, "src", "webview");
const FIXTURES = path.join(ROOT, "test", "fixtures");
const HAVE_TSHARK = spawnSync("tshark", ["--version"]).status === 0;

/** playwright-core + the compiled BackendClient, or null when unavailable. */
function loadDeps() {
  try {
    const { chromium } = require("playwright-core");
    const { BackendClient, findPython } = require(
      path.join(ROOT, "out", "src", "backendClient.js"),
    );
    return { chromium, BackendClient, findPython };
  } catch {
    return null;
  }
}

/**
 * Serve src/webview's files (and codicons/), and with `media` (a folder) its files under
 * /media/ (the VoIP panel's audio, like the panel's own local resource root).
 */
function serveWebview({ media } = {}) {
  const types = {
    ".js": "text/javascript",
    ".css": "text/css",
    ".ttf": "font/ttf",
    ".wav": "audio/wav",
  };
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://x").pathname;
    const dir =
      media && pathname.startsWith("/media/")
        ? media
        : pathname.startsWith("/codicons/")
          ? path.join(WEBVIEW, "codicons")
          : pathname.startsWith("/viewer/")
            ? path.join(WEBVIEW, "viewer")
            : WEBVIEW;
    const file = path.join(dir, path.basename(pathname));
    if (!file.startsWith(dir) || !fs.existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    // (Fonts load in CORS mode; VS Code's webview resource server allows any origin too.)
    res.writeHead(200, {
      "content-type": types[path.extname(file)] || "application/octet-stream",
      "access-control-allow-origin": "*",
    });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

/** Stand-in for VS Code's acquireVsCodeApi, bridged to `window.__toHost` (page.exposeFunction). */
function stubScript(nonce) {
  return `<script nonce="${nonce}">
    window.acquireVsCodeApi = () => ({
      postMessage: (m) => window.__toHost(JSON.stringify(m)),
      getState: () => undefined,
      setState: () => undefined,
    });
  </script>`;
}

/** The capture editor page (src/webview/index.html), as pcapEditor.ts renders it. */
function renderEditorHtml(origin) {
  const nonce = crypto.randomBytes(16).toString("base64");
  const values = {
    cspSource: origin,
    nonce,
    baseUri: `${origin}/base.css`,
    stylesUri: `${origin}/styles.css`,
    codiconsUri: `${origin}/codicons/codicon.css`,
    libUri: `${origin}/lib.js`,
    mainUri: `${origin}/main.js`,
  };
  return fs
    .readFileSync(path.join(WEBVIEW, "index.html"), "utf8")
    .replace(/\{\{(\w+)\}\}/g, (_m, k) => values[k])
    .replace("<script", `${stubScript(nonce)}\n  <script`);
}

/** A statistics / follow panel page, mirroring src/panels/panelHtml.ts. */
function renderPanelHtml(origin, script, { media = false } = {}) {
  const nonce = crypto.randomBytes(16).toString("base64");
  const mediaSrc = media ? ` media-src ${origin};` : "";
  const csp = `default-src 'none'; img-src ${origin} data:; style-src ${origin}; font-src ${origin};${mediaSrc} script-src 'nonce-${nonce}'`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <link rel="stylesheet" href="${origin}/codicons/codicon.css">
  <link rel="stylesheet" href="${origin}/base.css"><link rel="stylesheet" href="${origin}/panel.css">
  <title>${script}</title>
  </head><body class="panel"><div id="app"></div>
  ${stubScript(nonce)}
  <script nonce="${nonce}" src="${origin}/lib.js"></script>
  <script nonce="${nonce}" src="${origin}/${script}"></script>
  </body></html>`;
}

/** Start the backend with PCAP_VIEWER_PYTHON, else the uv .venv interpreter. */
async function startBackend(deps) {
  const venv = path.join(
    ROOT,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  const py = deps.findPython(
    process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venv) ? venv : undefined),
  );
  if ("error" in py) {
    throw new Error(py.error);
  }
  const client = new deps.BackendClient({
    python: py.python,
    backendDir: path.join(ROOT, "backend"),
    logger: { info() {}, warn() {}, error: (m) => console.error(m) },
  });
  startIsolated(client);
  await client.request("initialize", {});
  return client;
}

/**
 * Start the backend with an empty home, as test/backend/conftest.py runs
 * pytest: tshark reads the personal configuration and loads personal plugins
 * from the home folder, so a developer's own Wireshark setup must not change
 * what the tests see. The mocha process keeps its own environment (Playwright
 * finds its browsers under ~/.cache): only the backend's spawn sees the swap.
 */
const ISOLATED_ENV = [
  "HOME",
  "APPDATA",
  "XDG_CONFIG_HOME",
  "WIRESHARK_CONFIG_DIR",
  "WIRESHARK_PLUGIN_DIR",
];
function startIsolated(client) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pcapviewer-home-"));
  process.on("exit", () => fs.rmSync(home, { recursive: true, force: true }));
  const saved = ISOLATED_ENV.map((name) => [name, process.env[name]]);
  for (const name of ISOLATED_ENV) {
    delete process.env[name];
  }
  Object.assign(process.env, {
    HOME: home,
    APPDATA: home, // Windows: %APPDATA%\Wireshark
    XDG_CONFIG_HOME: path.join(home, ".config"),
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

/** A page that records script errors and CSP violations. */
async function newPage(browser) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
  const problems = { errors: [], csp: [], page };
  page.on("pageerror", (err) => problems.errors.push(err.message));
  page.on("console", (m) => {
    if (/Content Security Policy/i.test(m.text())) {
      problems.csp.push(m.text());
    }
  });
  const post = (msg) => page.evaluate((m) => window.postMessage(m, "*"), msg);
  return { page, problems, post };
}

/** Whether the page's Codicons font loaded (codicons/codicon.css, allowed by the CSP's font-src). */
async function codiconFontLoaded(page) {
  return page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].some(
      (f) => f.family.replace(/"/g, "") === "codicon" && f.status === "loaded",
    );
  });
}

/**
 * axe-core's WCAG 2.x A/AA violations on the page, as "rule (impact): targets"
 * lines. axe is evaluated through the debugging protocol, so the page's CSP
 * doesn't apply to it.
 */
async function axeViolations(page, { exclude = [], disable = [] } = {}) {
  const source = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
  await page.evaluate(source);
  const violations = await page.evaluate(
    async ([exclude, disable]) =>
      /** @type {any} */ (window).axe
        .run(
          { include: [document], exclude },
          {
            runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
            rules: Object.fromEntries(disable.map((id) => [id, { enabled: false }])),
            resultTypes: ["violations"],
            // (axe would fetch the stylesheets for css-orientation-lock; the CSP refuses)
            preload: false,
          },
        )
        .then((r) => r.violations),
    [exclude, disable],
  );
  return violations.map(
    (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`,
  );
}

module.exports = {
  axeViolations,
  codiconFontLoaded,
  ROOT,
  WEBVIEW,
  FIXTURES,
  HAVE_TSHARK,
  loadDeps,
  serveWebview,
  renderEditorHtml,
  renderPanelHtml,
  startBackend,
  newPage,
};
