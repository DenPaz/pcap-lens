/**
 * Screenshots for the README and the Marketplace page (media/screenshots/):
 * the real webview pages in Chromium with VS Code's Dark Modern colors,
 * driven by the real backend and tshark on media/sample.pcapng, like the
 * Chromium tests (test/webview/harness.js). Needs `pnpm run compile` first.
 * Set CHROMIUM_PATH to use another Chromium build.
 *
 *   node scripts/screenshots.js [--theme dark|light|hc] [--out <folder>]
 *
 * The default (dark) run also writes viewer-light.png and demo.gif (filtering
 * with autocomplete, then a packet's tree and bytes) for the README.
 * `--theme light` (Light Modern) and `--theme hc` (Dark High Contrast) render
 * every screenshot in that theme, for checking the styling.
 */
const fs = require("node:fs");
const path = require("node:path");
const { Buffer } = require("node:buffer");
const {
  ROOT,
  loadDeps,
  serveWebview,
  renderEditorHtml,
  renderPanelHtml,
  startBackend,
} = require("../test/webview/harness");

/** `--name value` from the command line. */
function option(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const OUT = path.resolve(option("out", path.join(ROOT, "media", "screenshots")));
const SAMPLE = path.join(ROOT, "media", "sample.pcapng");
const VIEWPORT = { width: 1280, height: 760 };
/** demo.gif: smaller, so it stays legible when the README scales it down. */
const DEMO_VIEWPORT = { width: 1000, height: 600 };

/** VS Code's Dark Modern theme, for the variables the webviews use. */
const DARK_MODERN = {
  "font-family": "system-ui, 'Segoe UI', Ubuntu, 'Droid Sans', sans-serif",
  "font-size": "13px",
  "editor-font-family": "Consolas, 'DejaVu Sans Mono', 'Courier New', monospace",
  "editor-font-size": "13px",
  foreground: "#cccccc",
  descriptionForeground: "#9d9d9d",
  errorForeground: "#f85149",
  focusBorder: "#0078d4",
  "icon-foreground": "#cccccc",
  "widget-border": "#313131",
  "widget-shadow": "rgba(0, 0, 0, 0.36)",
  "sash-hoverBorder": "#0078d4",
  "textLink-foreground": "#4daafc",
  "textPreformat-foreground": "#d0d0d0",
  "textBlockQuote-background": "#2b2b2b",
  "editor-background": "#1f1f1f",
  "editor-foreground": "#cccccc",
  "editor-selectionBackground": "#264f78",
  "editor-selectionForeground": "#ffffff",
  "editor-inactiveSelectionBackground": "#3a3d41",
  "editorLineNumber-foreground": "#6e7681",
  "editorWidget-background": "#202020",
  "editorWidget-border": "#313131",
  "editorWarning-foreground": "#cca700",
  "editorInfo-foreground": "#3794ff",
  "editorHoverWidget-background": "#202020",
  "editorHoverWidget-foreground": "#cccccc",
  "editorHoverWidget-border": "#454545",
  "editorSuggestWidget-background": "#202020",
  "editorSuggestWidget-foreground": "#cccccc",
  "editorSuggestWidget-border": "#454545",
  "editorSuggestWidget-highlightForeground": "#2aaaff",
  "editorGroupHeader-tabsBackground": "#181818",
  "input-background": "#313131",
  "input-foreground": "#cccccc",
  "input-border": "#3c3c3c",
  "inputValidation-errorBackground": "#5a1d1d",
  "inputValidation-errorForeground": "#cccccc",
  "inputValidation-errorBorder": "#be1100",
  "dropdown-background": "#313131",
  "dropdown-foreground": "#cccccc",
  "dropdown-border": "#3c3c3c",
  "button-background": "#0078d4",
  "button-foreground": "#ffffff",
  "button-hoverBackground": "#026ec1",
  "button-border": "rgba(255, 255, 255, 0.07)",
  "button-secondaryBackground": "#313131",
  "button-secondaryForeground": "#cccccc",
  "button-secondaryHoverBackground": "#3c3c3c",
  "list-hoverBackground": "#2a2d2e",
  "list-activeSelectionBackground": "#04395e",
  "list-activeSelectionForeground": "#ffffff",
  "list-inactiveSelectionBackground": "#37373d",
  "list-inactiveSelectionForeground": "#cccccc",
  "list-focusOutline": "#0078d4",
  "menu-background": "#1f1f1f",
  "menu-foreground": "#cccccc",
  "menu-border": "#454545",
  "menu-selectionBackground": "#0078d4",
  "menu-selectionForeground": "#ffffff",
  "menu-separatorBackground": "#454545",
  "tab-activeBackground": "#1f1f1f",
  "tab-activeForeground": "#ffffff",
  "tab-inactiveBackground": "#181818",
  "tab-inactiveForeground": "#9d9d9d",
  "toolbar-hoverBackground": "rgba(90, 93, 94, 0.31)",
  "toolbar-activeBackground": "rgba(99, 102, 103, 0.31)",
  "panel-border": "#2b2b2b",
  "progressBar-background": "#0078d4",
  "charts-blue": "#3794ff",
  "charts-red": "#f14c4c",
  "testing-iconPassed": "#73c991",
};

const FONTS = {
  "font-family": DARK_MODERN["font-family"],
  "font-size": DARK_MODERN["font-size"],
  "editor-font-family": DARK_MODERN["editor-font-family"],
  "editor-font-size": DARK_MODERN["editor-font-size"],
};

/** VS Code's Light Modern theme. */
const LIGHT_MODERN = {
  ...FONTS,
  foreground: "#3b3b3b",
  descriptionForeground: "#3b3b3b",
  errorForeground: "#f85149",
  focusBorder: "#005fb8",
  "icon-foreground": "#3b3b3b",
  "widget-border": "#e5e5e5",
  "widget-shadow": "rgba(0, 0, 0, 0.16)",
  "sash-hoverBorder": "#005fb8",
  "textLink-foreground": "#005fb8",
  "textPreformat-foreground": "#3b3b3b",
  "textBlockQuote-background": "#f8f8f8",
  "editor-background": "#ffffff",
  "editor-foreground": "#3b3b3b",
  "editor-selectionBackground": "#add6ff",
  "editor-inactiveSelectionBackground": "#e5ebf1",
  "editorLineNumber-foreground": "#6e7681",
  "editorWidget-background": "#f8f8f8",
  "editorWidget-border": "#c8c8c8",
  "editorWarning-foreground": "#bf8803",
  "editorInfo-foreground": "#1a85ff",
  "editorHoverWidget-background": "#f8f8f8",
  "editorHoverWidget-foreground": "#3b3b3b",
  "editorHoverWidget-border": "#c8c8c8",
  "editorSuggestWidget-background": "#f8f8f8",
  "editorSuggestWidget-foreground": "#3b3b3b",
  "editorSuggestWidget-border": "#c8c8c8",
  "editorSuggestWidget-highlightForeground": "#0066bf",
  "editorGroupHeader-tabsBackground": "#f8f8f8",
  "input-background": "#ffffff",
  "input-foreground": "#3b3b3b",
  "input-border": "#cecece",
  "inputValidation-errorBackground": "#f2dede",
  "inputValidation-errorForeground": "#3b3b3b",
  "inputValidation-errorBorder": "#be1100",
  "dropdown-background": "#ffffff",
  "dropdown-foreground": "#3b3b3b",
  "dropdown-border": "#cecece",
  "button-background": "#005fb8",
  "button-foreground": "#ffffff",
  "button-hoverBackground": "#0258a8",
  "button-border": "rgba(0, 0, 0, 0.1)",
  "button-secondaryBackground": "#e5e5e5",
  "button-secondaryForeground": "#3b3b3b",
  "button-secondaryHoverBackground": "#cccccc",
  "list-hoverBackground": "#f2f2f2",
  "list-activeSelectionBackground": "#e8e8e8",
  "list-activeSelectionForeground": "#000000",
  "list-inactiveSelectionBackground": "#e4e6f1",
  "list-inactiveSelectionForeground": "#3b3b3b",
  "list-focusOutline": "#005fb8",
  "menu-background": "#ffffff",
  "menu-foreground": "#3b3b3b",
  "menu-border": "#cecece",
  "menu-selectionBackground": "#005fb8",
  "menu-selectionForeground": "#ffffff",
  "menu-separatorBackground": "#d4d4d4",
  "tab-activeBackground": "#ffffff",
  "tab-activeForeground": "#3b3b3b",
  "tab-inactiveBackground": "#f8f8f8",
  "tab-inactiveForeground": "#868686",
  "toolbar-hoverBackground": "rgba(184, 184, 184, 0.31)",
  "toolbar-activeBackground": "rgba(166, 166, 166, 0.31)",
  "panel-border": "#e5e5e5",
  "progressBar-background": "#005fb8",
  "charts-blue": "#1a85ff",
  "charts-red": "#e51400",
  "testing-iconPassed": "#388a34",
};

/**
 * VS Code's Dark High Contrast theme: borders instead of fills, so it leaves
 * the hover, selection and secondary-button backgrounds undefined.
 */
const HIGH_CONTRAST = {
  ...FONTS,
  foreground: "#ffffff",
  descriptionForeground: "rgba(255, 255, 255, 0.7)",
  errorForeground: "#f48771",
  focusBorder: "#f38518",
  contrastBorder: "#6fc3df",
  contrastActiveBorder: "#f38518",
  "icon-foreground": "#ffffff",
  "widget-border": "#6fc3df",
  "sash-hoverBorder": "#f38518",
  "textLink-foreground": "#21a6ff",
  "textPreformat-foreground": "#ffffff",
  "textBlockQuote-background": "#000000",
  "editor-background": "#000000",
  "editor-foreground": "#ffffff",
  "editor-selectionBackground": "#ffffff",
  "editor-selectionForeground": "#000000",
  "editorLineNumber-foreground": "#ffffff",
  "editorWidget-background": "#0c141f",
  "editorWidget-border": "#6fc3df",
  "editorWarning-foreground": "#ffd370",
  "editorInfo-foreground": "#3794ff",
  "editorHoverWidget-background": "#0c141f",
  "editorHoverWidget-foreground": "#ffffff",
  "editorHoverWidget-border": "#6fc3df",
  "editorSuggestWidget-background": "#0c141f",
  "editorSuggestWidget-foreground": "#ffffff",
  "editorSuggestWidget-border": "#6fc3df",
  "editorSuggestWidget-highlightForeground": "#f38518",
  "editorGroupHeader-tabsBackground": "#000000",
  "input-background": "#000000",
  "input-foreground": "#ffffff",
  "input-border": "#6fc3df",
  "inputValidation-errorBackground": "#000000",
  "inputValidation-errorBorder": "#6fc3df",
  "dropdown-background": "#000000",
  "dropdown-foreground": "#ffffff",
  "dropdown-border": "#6fc3df",
  "button-foreground": "#ffffff",
  "button-border": "#6fc3df",
  "button-secondaryForeground": "#ffffff",
  "list-focusOutline": "#f38518",
  "list-hoverForeground": "#ffffff",
  "menu-background": "#000000",
  "menu-foreground": "#ffffff",
  "menu-border": "#6fc3df",
  "menu-selectionBorder": "#f38518",
  "menu-separatorBackground": "#6fc3df",
  "tab-activeForeground": "#ffffff",
  "tab-inactiveForeground": "#ffffff",
  "tab-border": "#6fc3df",
  "toolbar-hoverOutline": "#f38518",
  "panel-border": "#6fc3df",
  "progressBar-background": "#6fc3df",
  "charts-blue": "#3794ff",
  "charts-red": "#f14c4c",
  "testing-iconPassed": "#73c991",
};

/** --theme → [variables, the <body> class VS Code sets]. */
const THEMES = {
  dark: [DARK_MODERN, "vscode-dark"],
  light: [LIGHT_MODERN, "vscode-light"],
  hc: [HIGH_CONTRAST, "vscode-high-contrast"],
};
const THEME = option("theme", "dark");
if (!THEMES[THEME]) {
  throw new Error(`--theme must be one of ${Object.keys(THEMES).join(", ")}`);
}

/** Apply the theme the way VS Code does (variables on <html>, a class on <body>). */
function applyTheme(page, theme = THEME) {
  const [vars, kind] = THEMES[theme];
  return page.evaluate(
    ([vars, kind]) => {
      for (const [k, v] of Object.entries(vars)) {
        document.documentElement.style.setProperty(`--vscode-${k}`, v);
      }
      document.body.classList.add(kind);
    },
    [vars, kind],
  );
}

/**
 * Encode PNG screenshots as one looping GIF: one palette for all frames,
 * and pixels unchanged since the previous frame left transparent (kept from
 * it), so a mostly still UI stays small.
 * @param {{png: Buffer, delay: number}[]} frames delay in ms
 */
function encodeGif(frames) {
  const { PNG } = require("pngjs");
  const { GIFEncoder, quantize, applyPalette } = require("gifenc");
  const images = frames.map((f) => PNG.sync.read(f.png));
  const { width, height } = images[0];
  const all = new Uint8Array(images.length * width * height * 4);
  images.forEach((img, i) => all.set(img.data, i * width * height * 4));
  // 255 colors; index 255 is the "unchanged" (transparent) one.
  const palette = quantize(all, 255, { format: "rgb565" });
  while (palette.length < 256) {
    palette.push([0, 0, 0]);
  }
  const KEEP = 255;
  const gif = GIFEncoder();
  let previous = null;
  images.forEach((img, i) => {
    const index = applyPalette(img.data, palette.slice(0, 255), "rgb565");
    const frame = previous ? index.map((v, p) => (v === previous[p] ? KEEP : v)) : index;
    gif.writeFrame(frame, width, height, {
      palette: i === 0 ? palette : undefined,
      delay: frames[i].delay,
      transparent: i > 0,
      transparentIndex: KEEP,
      dispose: 1,
    });
    previous = index;
  });
  gif.finish();
  return Buffer.from(gif.bytes());
}

/** Record demo.gif: type a filter with autocomplete, apply it, open a packet. */
async function recordDemo(browser, origin, client, rules) {
  const page = await editorPage(browser, origin, client, rules, "dark", DEMO_VIEWPORT);
  const frames = [];
  const shot = async (delay) => frames.push({ png: await page.screenshot(), delay });
  await shot(1500);
  await page.click("#filter-input");
  for (const [i, ch] of [..."dns || http"].entries()) {
    await page.keyboard.type(ch);
    if (i === 2) {
      await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    }
    await page.waitForTimeout(80);
    await shot(i === 2 ? 1200 : 140);
  }
  await page.keyboard.press("Enter"); // nothing is preselected: Enter applies
  await page.waitForFunction(() =>
    /Displayed: 8/.test(document.querySelector("#status-left").textContent),
  );
  await shot(1400);
  await page.click("#list-rows .list-row:has-text('200 OK')");
  await page.waitForSelector("#detail-tree .node-row:has-text('Hypertext Transfer Protocol')");
  await shot(1000);
  await page.click("#detail-tree .node-row:has-text('Hypertext Transfer Protocol') .twisty");
  await shot(900);
  await page.click("#detail-tree .node-row:has-text('Content-Type')");
  await shot(3000);
  await page.close();
  return encodeGif(frames);
}

/** Forward the webview's rpc messages to the backend (see src/pcapEditor.ts). */
function forwardRpc(client, post, msg) {
  client.request(msg.method, msg.params, { timeoutMs: 0 }).then(
    (result) => post({ type: "rpcResult", id: msg.id, result }),
    (err) =>
      post({ type: "rpcError", id: msg.id, error: { code: err.code, message: err.message } }),
  );
}

/** Filter buttons (pcapViewer.filterButtons) for the toolbar under the filter bar. */
const FILTER_BUTTONS = [
  { label: "Web", filter: "http || tls" },
  { label: "DNS errors", filter: "dns.flags.rcode != 0" },
  { label: "TCP handshakes", filter: "tcp.flags.syn == 1" },
];

async function editorPage(browser, origin, client, rules, theme = THEME, viewport = VIEWPORT) {
  const page = await browser.newPage({ viewport });
  // (answers can still arrive after the page closed)
  const post = (m) => page.evaluate((x) => window.postMessage(x, "*"), m).catch(() => undefined);
  await page.exposeFunction("__toHost", async (raw) => {
    const msg = JSON.parse(raw);
    if (msg.type === "ready") {
      const info = await client.request(
        "open",
        {
          path: SAMPLE,
          coloring: {
            rules: rules.map((r) => ({
              filter: r.filter,
              foreground: r.foreground,
              background: r.background,
            })),
          },
        },
        { timeoutMs: 0 },
      );
      await post({
        type: "init",
        info,
        columns: [],
        layout: { order: [], hidden: [] },
        timeFormat: "relative",
        quickDetail: { after: 20000, window: 300 },
        filter: "",
        history: ["tcp.port == 80", "dns.flags.rcode != 0"],
        savedFilters: [{ name: "Web", filter: "http || tls" }],
        elapsedMs: 40,
        names: "Names: off",
      });
      await post({ type: "filterButtons", buttons: FILTER_BUTTONS });
      await post({ type: "coloring", coloringId: info.coloring.coloringId, rules });
    } else if (msg.type === "rpc") {
      forwardRpc(client, post, msg);
    }
  });
  await page.setContent(renderEditorHtml(origin), { waitUntil: "load" });
  await applyTheme(page, theme);
  await page.waitForSelector("#overlay.hidden", { state: "attached" });
  await page.waitForSelector("#list-rows .list-row");
  return page;
}

async function main() {
  const deps = loadDeps();
  if (!deps) {
    throw new Error("run `pnpm run compile` first (and install playwright-core)");
  }
  fs.mkdirSync(OUT, { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const rules = pkg.contributes.configuration.properties["pcapViewer.coloringRules"].default;
  const server = await serveWebview();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const client = await startBackend(deps);
  const browser = await deps.chromium.launch(
    process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
  );
  try {
    // 1. The viewer: an HTTP response reassembled from two segments, its tree open.
    const viewer = async (page, file) => {
      await page.click("#list-rows .list-row >> nth=15");
      await page.waitForSelector("#detail-tree .node-row:has-text('Hypertext Transfer Protocol')");
      await page.click("#detail-tree .node-row:has-text('Hypertext Transfer Protocol') .twisty");
      await page.click("#detail-tree .node-row:has-text('Content-Type')");
      await page.screenshot({ path: path.join(OUT, file) });
    };
    let page = await editorPage(browser, origin, client, rules);
    await viewer(page, "viewer.png");

    // 2. Filter autocomplete from tshark's field list.
    await page.click("#filter-input");
    await page.keyboard.type("dns.flags.r", { delay: 20 });
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    await page.screenshot({ path: path.join(OUT, "filter.png") });
    await page.close();

    // 3. Protocol hierarchy statistics.
    page = await browser.newPage({ viewport: { width: 1000, height: 380 } });
    // (answers can still arrive after the page closed)
    const post = (m) => page.evaluate((x) => window.postMessage(x, "*"), m).catch(() => undefined);
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type === "ready") {
        await post({ type: "init", kind: "phs", title: "Protocol Hierarchy", filter: "" });
      } else if (msg.type === "query") {
        const table = await client.request("stats", { kind: "phs", filter: "" });
        await post({ type: "result", id: msg.id, table });
      }
    });
    await page.setContent(renderPanelHtml(origin, "stats.js"), { waitUntil: "load" });
    await applyTheme(page);
    await page.waitForSelector("table.stats tbody tr");
    await page.screenshot({ path: path.join(OUT, "statistics.png") });
    await page.close();

    // 4. The viewer in a light theme (README).
    if (THEME === "dark") {
      page = await editorPage(browser, origin, client, rules, "light");
      await viewer(page, "viewer-light.png");
      await page.close();

      // 5. An animated tour (README).
      fs.writeFileSync(
        path.join(OUT, "demo.gif"),
        await recordDemo(browser, origin, client, rules),
      );
    }
  } finally {
    await browser.close();
    await client.dispose();
    server.close();
  }
  console.log(`screenshots written to ${path.relative(ROOT, OUT)}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
