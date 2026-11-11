/**
 * The basic view in headless Chromium: the real webview with a stand-in host
 * that answers its requests from BasicCapture (src/basicCapture.ts, compiled),
 * as PcapEditorSession does when Python or tshark is missing. No tshark needed.
 */
const assert = require("node:assert/strict");
const path = require("node:path");
const {
  ROOT,
  loadDeps,
  serveWebview,
  renderEditorHtml,
  axeViolations,
  trackCoverage,
  FIXTURES,
} = require("./harness");

const deps = loadDeps();
const maybe = deps ? suite : suite.skip;

maybe("webview basic view (Chromium, no tshark)", function () {
  this.timeout(60_000);
  const { BasicCapture, BASIC_COLUMNS, basicRequest } = deps
    ? require(path.join(ROOT, "out", "src", "basicCapture.js"))
    : {};
  let server, browser, page, capture;
  const hostLog = [];
  const pageErrors = [];
  const post = (msg) => page.evaluate((m) => window.postMessage(m, "*"), msg);
  /** The session's `init` for the basic view (PcapEditorSession.showBasic). */
  const initMessage = () => {
    const span = capture.timeSpan();
    return {
      type: "init",
      info: {
        path: capture.path,
        frames: capture.count,
        startTime: span.start,
        endTime: span.end,
        linkType: capture.linkTypeName(),
        fileType: capture.fileType,
        size: capture.size,
        warnings: [],
        columns: BASIC_COLUMNS,
        filterId: 1,
      },
      columns: [{ field: "tcp.stream", title: "Stream" }],
      layout: { order: [], hidden: [] },
      timeFormat: "relative",
      quickDetail: { after: 20000, window: 300 },
      filter: "",
      history: [],
      savedFilters: [],
      elapsedMs: 0,
      names: "",
      lua: "",
      basic: { missing: "tshark", reason: "tshark was not found (searched: PATH)" },
    };
  };

  suiteSetup(async function () {
    server = await serveWebview();
    const origin = `http://127.0.0.1:${server.address().port}`;
    capture = await BasicCapture.open(path.join(FIXTURES, "http.pcap"));
    try {
      browser = await deps.chromium.launch();
      trackCoverage(browser);
    } catch (err) {
      console.warn(
        `skipping basic view e2e: no Chromium available (${err.message.split("\n")[0]})`,
      );
      this.skip();
    }
    page = await browser.newPage({ viewport: { width: 1000, height: 700 } });
    page.on("pageerror", (err) => pageErrors.push(err.message));
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      hostLog.push(msg);
      if (msg.type === "ready") {
        await post(initMessage());
      } else if (msg.type === "rpc") {
        try {
          const result = basicRequest(capture, msg.method, msg.params ?? {});
          await post({ type: "rpcResult", id: msg.id, result });
        } catch (err) {
          await post({
            type: "rpcError",
            id: msg.id,
            error: { code: -32001, message: err.message },
          });
        }
      }
    });
    await page.setContent(renderEditorHtml(origin), { waitUntil: "load" });
  });

  suiteTeardown(async () => {
    await browser?.close();
    capture?.close();
    server?.close();
  });

  test("the packets, with a banner saying what is missing; filters are off", async () => {
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    const banner = await page.$eval("#basic-banner", (b) => ({
      hidden: b.classList.contains("hidden"),
      text: b.textContent,
      title: b.getAttribute("title"),
    }));
    assert.equal(banner.hidden, false);
    assert.match(banner.text, /Basic view: Wireshark's tshark wasn't found/);
    assert.equal(banner.title, "tshark was not found (searched: PATH)");
    assert.equal(await page.isDisabled("#filter-input"), true);
    assert.match(await page.getAttribute("#filter-input", "placeholder"), /need tshark/);
    const cells = await page.$$eval("#list-rows .list-row:not(.loading)", (rows) =>
      [...rows[3].children].map((c) => c.textContent),
    );
    assert.ok(
      cells.includes("HTTP") && cells.includes("GET /index.html HTTP/1.1"),
      cells.join("|"),
    );
  });

  test("a packet's details and bytes, linked both ways", async () => {
    await page.click("#list-rows .list-row:nth-child(4)");
    await page.waitForFunction(() =>
      [...document.querySelectorAll("#detail .node-row")].some((r) =>
        /^Internet Protocol Version 4/.test(r.textContent.trim()),
      ),
    );
    const labels = await page.$$eval("#detail .node-row", (rows) =>
      rows.map((r) => r.textContent.trim()),
    );
    assert.match(labels[0], /^Frame 4: 144 bytes on wire/);
    assert.ok(labels.some((l) => l.startsWith("Hypertext Transfer Protocol")));
    // A byte of the source address selects its field.
    await page.click("#bytes [data-i='26']");
    await page.waitForFunction(() =>
      /Source Address: 192\.168\.1\.10/.test(
        document.querySelector("#detail .node-row.selected")?.textContent ?? "",
      ),
    );
  });

  test("comments can't be edited, and an earlier filter doesn't carry over (Codex review)", async () => {
    // A packet is selected (previous test): editing its comment says why not.
    await post({ type: "command", command: "editPacketComment" });
    await page.waitForFunction(() =>
      /Packet comments need tshark/.test(document.getElementById("filter-error").textContent),
    );
    assert.equal(await page.isVisible("#comment-editor"), false);
    assert.ok(!hostLog.some((m) => m.type === "setComment"));
    // A filter left in the box by a full load: a basic init shows every packet.
    await page.evaluate(() => {
      const input = /** @type {HTMLInputElement} */ (document.getElementById("filter-input"));
      input.disabled = false;
      input.value = "tcp.port == 80";
    });
    hostLog.length = 0;
    await post(initMessage());
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    assert.equal(await page.inputValue("#filter-input"), "");
    assert.ok(
      !hostLog.some((m) => m.type === "rpc" && m.method === "set_filter"),
      "no filter is applied",
    );
    await page.click("#list-rows .list-row:nth-child(4)");
    await page.waitForSelector("#detail .node-row");
  });

  test("sorting says it needs tshark; Set Up… and Reload reach the host", async () => {
    await page.click("#list-header > div[data-id='info']");
    await page.waitForFunction(() =>
      /Sorting needs tshark/.test(document.getElementById("filter-error").textContent),
    );
    await page.click("#basic-setup");
    await page.click("#basic-reload");
    const start = Date.now();
    while (!hostLog.some((m) => m.type === "reload") && Date.now() - start < 5000) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(hostLog.some((m) => m.type === "setUp"));
    assert.ok(hostLog.some((m) => m.type === "reload"));
    // (Without a theme, the bytes' highlight falls back to colors axe flags, as in e2e.test.js.)
    assert.deepEqual(await axeViolations(page, { exclude: [["#bytes"]] }), []);
    assert.deepEqual(pageErrors, []);
  });
});
