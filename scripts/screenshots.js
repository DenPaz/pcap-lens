/**
 * Screenshots for the README and the Marketplace page (media/screenshots/):
 * the real webview pages in Chromium with VS Code's Dark Modern colors,
 * driven by the real backend and tshark on media/sample.pcapng, like the
 * Chromium tests (test/webview/harness.js). Needs `pnpm run compile` first.
 * Set CHROMIUM_PATH to use another Chromium build.
 *
 *   node scripts/screenshots.js [--theme dark|light|hc] [--out <folder>]
 *
 * Writes viewer.png, diagram.png (the packet diagram), filter.png and
 * statistics.png. The default (dark) run also writes viewer-light.png and demo.gif (filtering
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
const { THEMES, applyTheme: applyThemeTo } = require("./themes");

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

const THEME = option("theme", "dark");
/** @param {import("playwright-core").Page} page */
const applyTheme = (page, theme = THEME) => applyThemeTo(page, theme);
if (!THEMES[THEME]) {
  throw new Error(`--theme must be one of ${Object.keys(THEMES).join(", ")}`);
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

    // 1b. The same packet's TCP and IPv4 headers as a packet diagram.
    await page.click("#view-diagram");
    await page.waitForSelector(".pd-proto[aria-label='Transmission Control Protocol']");
    await page.click(
      ".pd-proto[aria-label='Internet Protocol Version 4'] .pd-cell:text-is('Time to Live')",
    );
    await page.evaluate(() =>
      document
        .querySelector(".pd-proto[aria-label='Internet Protocol Version 4']")
        ?.scrollIntoView({ block: "start" }),
    );
    await page.screenshot({ path: path.join(OUT, "diagram.png") });
    await page.click("#view-tree");

    // 1c. The packet list's menu with its Follow ▸ submenu.
    await page.click("#list-rows .list-row:has(div:text-is('HTTP')) >> nth=0 >> div >> nth=4", {
      button: "right",
    });
    await page.hover("#context-menu .item:has-text('Follow')");
    await page.waitForSelector("#context-menu-1 .item .label:text-is('HTTP Stream')");
    await page.hover("#context-menu-1 .item:has-text('HTTP Stream')");
    await page.screenshot({ path: path.join(OUT, "menus.png") });
    await page.keyboard.press("Escape");
    await page.keyboard.press("Escape");

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
