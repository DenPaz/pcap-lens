/**
 * End-to-end tests of the statistics and follow-stream panels (stats.js,
 * follow.js) in headless Chromium, with a stand-in host that forwards to the
 * real backend exactly like src/panels/*.ts does.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");
const {
  FIXTURES,
  HAVE_TSHARK,
  loadDeps,
  serveWebview,
  renderPanelHtml,
  startBackend,
  newPage,
  codiconFontLoaded,
  axeViolations,
} = require("./harness");

const deps = loadDeps();

/**
 * The stand-in host's last message, once `accept` takes it: messages reach the
 * host through an exposed function, asynchronously, so the action that posts
 * one can resolve before it arrives.
 */
async function lastMessage(log, accept, timeoutMs = 2000) {
  const end = Date.now() + timeoutMs;
  while (!(log.length && accept(log.at(-1))) && Date.now() < end) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return log.at(-1);
}

/** Assert the host's last message is `expected` (waiting for it to arrive). */
async function expectLast(log, expected) {
  assert.deepEqual(await lastMessage(log, (m) => isDeepStrictEqual(m, expected)), expected);
}

/** The host's last message, asserting its type (waiting for it to arrive). */
async function lastOfType(log, type) {
  const msg = await lastMessage(log, (m) => m.type === type);
  assert.equal(msg?.type, type);
  return msg;
}

const maybe = deps && HAVE_TSHARK ? suite : suite.skip;

const TITLES = {
  conversations: "Conversations",
  endpoints: "Endpoints",
  phs: "Protocol Hierarchy",
  io: "I/O Graph",
  expert: "Expert Information",
  properties: "Capture File Properties",
  http: "HTTP",
  dns: "DNS",
  plen: "Packet Lengths",
  srt: "Service Response Time",
  ipv4: "IPv4 Statistics",
  multicast: "UDP Multicast Streams",
  sctp: "SCTP Associations",
  hosts: "Resolved Addresses",
};

maybe("statistics and follow panels (Chromium + real backend)", function () {
  this.timeout(60_000);
  let server, browser, client, origin;
  const pages = [];
  // The VoIP panel's played audio (the panel's own local resource folder).
  const media = fs.mkdtempSync(path.join(os.tmpdir(), "pcapviewer-e2e-media-"));

  suiteSetup(async function () {
    server = await serveWebview({ media });
    origin = `http://127.0.0.1:${server.address().port}`;
    client = await startBackend(deps);
    await client.request("open", { path: path.join(FIXTURES, "mixed.pcapng") }, { timeoutMs: 0 });
    try {
      browser = await deps.chromium.launch();
    } catch (err) {
      console.warn(`skipping panel e2e: no Chromium available (${err.message.split("\n")[0]})`);
      this.skip();
    }
  });

  suiteTeardown(async () => {
    await browser?.close();
    await client?.dispose();
    server?.close();
    fs.rmSync(media, { recursive: true, force: true });
  });

  /** Open stats.js with a stand-in for StatsPanel (src/panels/statsPanel.ts). */
  async function openStats(
    kind,
    captureFilter = "",
    ai = false,
    io = undefined,
    { backend = client, scripts = [] } = {},
  ) {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await post({ type: "init", kind, title: TITLES[kind], filter: captureFilter, ai, io });
      } else if (msg.type === "query") {
        const params = {
          kind,
          type: msg.params.type,
          interval: msg.params.interval,
          filter: msg.params.limit ? captureFilter : "",
          series: msg.params.series,
        };
        backend.request("stats", params, { timeoutMs: 0 }).then(
          (table) => post({ type: "result", id: msg.id, table }),
          (err) =>
            post({
              type: "error",
              id: msg.id,
              message: err.message,
              cancelled: err.code === -32800,
              series: typeof err.data?.series === "number" ? err.data.series : undefined,
            }),
        );
      }
    });
    await page.setContent(renderPanelHtml(origin, "stats.js", { scripts }), { waitUntil: "load" });
    pages.push(problems);
    return { page, log };
  }

  const rows = (page) =>
    page.$$eval("table.stats tbody tr", (trs) =>
      trs.map((tr) => [...tr.children].map((td) => td.textContent)),
    );
  const waitRows = (page, n) =>
    page.waitForFunction(
      (count) => document.querySelectorAll("table.stats tbody tr").length === count,
      n,
    );

  test("endpoints: GeoIP columns and a map of the located endpoints", async () => {
    const geo = await startBackend(deps);
    try {
      await geo.request(
        "open",
        { path: path.join(FIXTURES, "mixed.pcapng"), geoip: [path.join(FIXTURES, "geoip")] },
        { timeoutMs: 0 },
      );
      const { page, log } = await openStats("endpoints", "", false, undefined, {
        backend: geo,
        scripts: ["worldmap.js"],
      });
      await page.selectOption("select[aria-label='Address type']", "ip");
      await page.waitForSelector("th:has-text('Country')");
      await waitRows(page, 6);
      assert.deepEqual(
        (await page.$$eval("table.stats th", (ths) => ths.map((th) => th.textContent))).slice(0, 5),
        ["Address", "Country", "City", "AS Number", "AS Organization"],
      );
      const google = (await rows(page)).find((r) => r[0] === "8.8.8.8");
      assert.deepEqual(google.slice(1, 3), ["United States", "Mountain View"]);
      assert.match(google[3], /^15,?169$/);
      assert.equal(google[4], "Google LLC");
      // One point per place, the busiest (example.com's 1,175 bytes) drawn first.
      const tips = await page.$$eval(".geo-map circle.geo-point title", (ts) =>
        ts.map((t) => t.textContent),
      );
      assert.deepEqual(tips, [
        "93.184.216.34, Norwell, United States",
        "8.8.8.8, Mountain View, United States",
      ]);
      assert.equal(
        await page.getAttribute(".geo-map svg", "aria-label"),
        "Map of 2 places with endpoints",
      );
      // Picking a point selects its row (and the point).
      await page.click(".geo-map circle.geo-point >> nth=1", { force: true });
      await page.waitForSelector(".geo-map circle.geo-point.selected");
      await page.click("button:has-text('Apply as Filter')");
      assert.equal(log.findLast((m) => m.type === "filter").expr, "ip.addr == 8.8.8.8");
      // Without GeoIP databases the map stays hidden (TCP endpoints have ports).
      await page.selectOption("select[aria-label='Address type']", "tcp");
      await page.waitForFunction(
        () => !document.querySelector("th:nth-child(2)")?.textContent?.includes("Country"),
      );
      assert.ok(await page.isHidden(".geo-map"));
    } finally {
      await geo.dispose();
    }
  });

  test("IPv4 statistics, multicast streams, SCTP and resolved addresses", async () => {
    const net = await startBackend(deps);
    try {
      await net.request("open", { path: path.join(FIXTURES, "network.pcap") }, { timeoutMs: 0 });
      const ipv4 = await openStats("ipv4", "", false, undefined, { backend: net });
      await ipv4.page.waitForSelector("table.stats tbody tr");
      assert.equal(await ipv4.page.textContent(".panel-title"), "IPv4 All Addresses");
      // A tree: no sorting; the report picker switches to destinations and ports.
      assert.equal(await ipv4.page.$("th[aria-sort]"), null);
      await ipv4.page.selectOption("#stats-type", "dests");
      await ipv4.page.waitForSelector(".panel-title:has-text('Destinations and Ports')");
      await ipv4.page.click("table.stats tbody tr:has-text('5001')");
      await ipv4.page.click("button:has-text('Apply as Filter')");
      assert.equal(
        ipv4.log.findLast((m) => m.type === "filter").expr,
        "ip.dst == 239.2.2.2 && udp.dstport == 5001",
      );

      const mc = await openStats("multicast", "", false, undefined, { backend: net });
      await waitRows(mc.page, 2);
      const first = (await rows(mc.page))[0];
      assert.deepEqual(first.slice(0, 5), ["10.1.1.5", "4,000", "239.1.1.1", "5,000", "80"]);
      assert.deepEqual(first.slice(8), ["60", "1"]); // max burst, burst alarms

      const sctp = await openStats("sctp", "udp", false, undefined, { backend: net });
      await waitRows(sctp.page, 2);
      await sctp.page.check("text=Limit to display filter");
      await sctp.page.waitForSelector(".status:has-text('covers the whole capture')");

      const hosts = await openStats("hosts", "", false, undefined, { backend: net });
      await waitRows(hosts.page, 1);
      assert.deepEqual((await rows(hosts.page))[0], ["10.1.1.5", "ntp.example.org"]);
    } finally {
      await net.dispose();
    }
  });

  test("conversations: type switch, sorting, row filter and CSV", async () => {
    const { page, log } = await openStats("conversations");
    await waitRows(page, 1);
    assert.equal(await page.textContent(".panel-title"), "TCP Conversations");
    assert.deepEqual((await rows(page))[0].slice(0, 3), [
      "192.168.1.10:50000",
      "93.184.216.34:80",
      "11",
    ]);

    await page.selectOption("select[aria-label='Address type']", "udp");
    await waitRows(page, 4);
    await page.click("th:has-text('Packets A → B')"); // numeric columns sort descending first
    const sorted = (await rows(page)).map((r) => r[4]);
    assert.deepEqual(
      sorted,
      [...sorted].sort((a, b) => Number(b) - Number(a)),
    );
    assert.equal(
      await page.$eval("th[aria-sort='descending'] .codicon", (i) => i.className),
      "codicon codicon-triangle-down",
    );
    assert.ok(await codiconFontLoaded(page), "the codicon font loads in panels");
    // Panels share base.css (tokens, controls) with the viewer, not its styles.css.
    assert.deepEqual(
      await page.evaluate(() => [
        [...document.styleSheets].map((s) => s.href.split("/").pop()),
        getComputedStyle(document.documentElement).getPropertyValue("--space-4"),
      ]),
      [["codicon.css", "base.css", "panel.css"], "8px"],
    );

    await page.click("table.stats tbody tr >> nth=0");
    await page.click("button:has-text('Apply as Filter')");
    const filter = log.find((m) => m.type === "filter");
    assert.equal(filter.apply, true);
    assert.match(
      filter.expr,
      /^ip\.addr == 10\.0\.0\.1 && udp\.port == 12345 && ip\.addr == 10\.0\.0\.2 && udp\.port == 9999$/,
    );

    await page.click("button:has-text('Copy as CSV')");
    const csv = log.find((m) => m.type === "copy").text.split("\n");
    assert.equal(
      csv[0],
      "Address A,Address B,Packets,Bytes,Packets A → B,Bytes A → B,Packets B → A,Bytes B → A,Rel Start,Duration",
    );
    assert.equal(csv.length, 5);
  });

  /** Pick a path through a page's context menus (menus.js): every label but the last opens a submenu. */
  async function pickMenu(page, ...path) {
    for (const label of path) {
      await page
        .locator(".context-menu:not(.hidden) .item")
        .filter({ has: page.locator(".label", { hasText: new RegExp(`^${escapeRe(label)}$`) }) })
        .last()
        .click();
    }
  }
  /** @param {string} text */
  const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const menuLabels = (page, level = 0) =>
    page.$$eval(`${level ? `#context-menu-${level}` : "#context-menu"} .item .label`, (els) =>
      els.map((e) => e.textContent),
    );

  test("statistics row menu: filters with the capture's, go to packet, copies", async () => {
    const { page, log } = await openStats("conversations", "http");
    await waitRows(page, 1);
    // Right-click a row: it is selected and its menu opens; Apply/Prepare as Filter
    // combine the row's filter with the capture's, each showing the filter it makes.
    await page.click("table.stats tbody tr >> nth=0 >> td >> nth=0", { button: "right" });
    await page.waitForSelector("#context-menu:not(.hidden)");
    assert.ok(await page.$eval("table.stats tbody tr", (tr) => tr.classList.contains("selected")));
    assert.deepEqual(await menuLabels(page), ["Apply as Filter", "Prepare as Filter", "Copy"]);
    await pickMenu(page, "Apply as Filter");
    await page.waitForSelector("#context-menu-1 .item");
    assert.deepEqual(await menuLabels(page, 1), [
      "Selected",
      "Not Selected",
      "…and Selected",
      "…or Selected",
      "…and not Selected",
      "…or not Selected",
    ]);
    await pickMenu(page, "…and Selected");
    const filter = log.findLast((m) => m.type === "filter");
    assert.equal(filter.apply, true);
    assert.match(filter.expr, /^\(http\) && \(ip\.addr == 192\.168\.1\.10 && tcp\.port == 50000/);
    assert.ok(await page.isHidden("#context-menu"));
    // Copy › Value copies the clicked cell; Shift+F10 opens the selected row's menu.
    await page.click("table.stats tbody tr >> nth=0 >> td >> nth=0", { button: "right" });
    await pickMenu(page, "Copy", "Value");
    assert.equal(log.findLast((m) => m.type === "copy").text, "192.168.1.10:50000");
    await page.focus("button:has-text('Refresh')");
    await page.keyboard.press("Shift+F10");
    assert.ok(await page.isHidden("#context-menu"), "the focus isn't in the table");
    // Expert rows go to their packet.
    const expert = await openStats("expert");
    await expert.page.waitForSelector("table.stats tbody tr");
    await expert.page.click("table.stats tbody tr >> nth=0", { button: "right" });
    const labels = await menuLabels(expert.page);
    assert.ok(
      labels.some((l) => /^Go to Packet \d+$/.test(l)),
      labels.join(", "),
    );
    await pickMenu(
      expert.page,
      labels.find((l) => l.startsWith("Go to Packet")),
    );
    assert.equal(typeof expert.log.findLast((m) => m.type === "goto").frame, "number");
    // Buttons carry an icon before their label.
    assert.equal(
      await page.$eval("button:has-text('Copy as CSV') .codicon", (i) => i.className),
      "codicon codicon-copy",
    );
  });

  test("limit to the capture's display filter", async () => {
    const { page } = await openStats("conversations", "http");
    await waitRows(page, 1);
    assert.equal((await rows(page))[0][2], "11");
    await page.check("input[type=checkbox]");
    await page.waitForFunction(
      () => document.querySelector("table.stats tbody tr td:nth-child(3)")?.textContent === "2",
    );
    assert.match(await page.textContent(".status"), /matching http/);
  });

  test("protocol hierarchy keeps the tree and indents by depth", async () => {
    const { page } = await openStats("phs");
    await waitRows(page, 11);
    // tshark 4.6 adds a top-level "frame" row (everything one level deeper than
    // 4.2), so compare depths instead of expecting absolute ones.
    const indent = (proto) =>
      page.$eval(`table.stats tbody tr:has(td:text-is('${proto}')) td`, (td) =>
        parseFloat(getComputedStyle(td).paddingLeft),
      );
    assert.equal((await indent("dns")) - (await indent("udp")), 16, "dns one level below udp");
    assert.equal((await indent("arp")) - (await indent("eth")), 16, "arp one level below eth");
    const names = (await rows(page)).map((r) => r[0]);
    const eth = names.indexOf("eth");
    assert.deepEqual(names.slice(eth, eth + 3), ["eth", "arp", "ip"]);
  });

  test("IO graph: line chart with crosshair tooltip, keyboard and metric switch", async () => {
    const { page } = await openStats("io");
    await page.waitForSelector(".chart svg .series-line");
    assert.ok((await page.getAttribute(".chart svg .series-line", "d")).startsWith("M"));
    assert.ok((await page.$$eval(".chart .axis text", (t) => t.length)) >= 4);
    const box = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForSelector(".chart .tooltip:not(.hidden)");
    assert.match(await page.textContent(".chart .tooltip strong"), /^\d+ packets$/);
    // A resize redraws the chart (e.g. when the table below gets a scrollbar):
    // the hovered point and its tooltip stay.
    const drawn = await page.$(".chart svg");
    await page.setViewportSize({ width: 1000, height: 800 });
    await page.waitForFunction((old) => document.querySelector(".chart svg") !== old, drawn);
    assert.equal(
      await page.$eval(".chart .tooltip", (t) => t.classList.contains("hidden")),
      false,
      "the tooltip survives a redraw",
    );
    const shrunk = await page.$(".chart svg");
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.waitForFunction((old) => document.querySelector(".chart svg") !== old, shrunk);
    const resized = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(resized.x + resized.width / 2, resized.y + resized.height / 2);
    await page.focus(".chart");
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowRight");
    assert.match(await page.textContent(".chart .tooltip span"), /^0\.00\d+–0\.00\d+ s$/);
    await page.selectOption("select[aria-label='Y axis of graph 1']", "bytes");
    await page.mouse.move(resized.x + resized.width / 2 + 5, resized.y + resized.height / 2);
    await page.waitForFunction(() =>
      /bytes$/.test(document.querySelector(".chart .tooltip strong")?.textContent ?? ""),
    );
  });

  test("IO graph: several graphs, a field's average, bars, log scale; a bad filter names its graph", async () => {
    const { page, log } = await openStats("io");
    await page.waitForSelector(".chart svg .series-line.s0");
    const lastQuery = () => log.filter((m) => m.type === "query").at(-1);
    await page.click("button:has-text('Add Graph')");
    await page.fill("input[aria-label='Display filter of graph 2']", "http");
    await page.press("input[aria-label='Display filter of graph 2']", "Enter");
    await page.waitForSelector(".chart svg .series-line.s1");
    assert.deepEqual(lastQuery().params.series, [
      { metric: "packets", filter: "", field: "" },
      { metric: "packets", filter: "http", field: "" },
    ]);
    // The table gets a column per graph; the legend names them.
    await page.waitForSelector("table.stats th:has-text('Packets · http')");
    assert.deepEqual(
      await page.$$eval(".io-legend li", (items) => items.map((i) => i.textContent)),
      ["Packets", "Packets · http"],
    );

    // A field metric asks for its field first, then draws its value.
    await page.click("button:has-text('Add Graph')");
    await page.selectOption("select[aria-label='Y axis of graph 3']", "avg");
    assert.ok(await page.isVisible("input[aria-label='Field of graph 3']"));
    await page.fill("input[aria-label='Field of graph 3']", "frame.len");
    await page.press("input[aria-label='Field of graph 3']", "Enter");
    await page.waitForSelector(".chart svg .series-line.s2");
    await page.selectOption("select[aria-label='Style of graph 3']", "bar");
    await page.waitForSelector(".chart svg .series-bars.s2 rect");
    assert.equal(await page.$(".chart svg .series-line.s2"), null, "drawn as bars instead");
    const box = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForSelector(".chart .tooltip .tooltip-row");
    assert.equal(await page.$$eval(".chart .tooltip .tooltip-row", (r) => r.length), 3);
    assert.match(
      await page.textContent(".chart .tooltip .tooltip-row:nth-child(3)"),
      /^AVG\(frame\.len\): [\d.]+$/,
    );

    await page.check("#io-log");
    await page.waitForFunction(() =>
      /log scale/.test(document.querySelector(".chart svg")?.getAttribute("aria-label") ?? ""),
    );
    // The host keeps the graphs (styles and log scale included) for the next I/O graph.
    const kept = log.filter((m) => m.type === "ioGraphs").at(-1);
    assert.equal(kept.logScale, true);
    assert.deepEqual(
      kept.series.map((g) => [g.metric, g.filter, g.field, g.style]),
      [
        ["packets", "", "", "line"],
        ["packets", "http", "", "line"],
        ["avg", "", "frame.len", "bar"],
      ],
    );

    // tshark refuses graph 2's filter: the notice and the input say which.
    await page.fill("input[aria-label='Display filter of graph 2']", "tcp.port ==");
    await page.press("input[aria-label='Display filter of graph 2']", "Enter");
    await page.waitForSelector(".notice.error:not(.hidden)");
    assert.match(await page.textContent(".notice.error"), /^Graph 2: /);
    assert.equal(
      await page.getAttribute("input[aria-label='Display filter of graph 2']", "aria-invalid"),
      "",
    );
    await page.click("button[aria-label='Remove graph 2']");
    await page.waitForFunction(
      () =>
        !document.querySelector(".notice.error") || document.querySelector(".notice.error.hidden"),
    );
    assert.equal(await page.$$eval(".io-graph", (rows) => rows.length), 2);
  });

  test("IO graph: starts with the graphs the host kept", async () => {
    const io = {
      series: [
        { metric: "bytes", filter: "tcp", field: "", style: "bar" },
        { metric: "max", filter: "", field: "frame.len", style: "line" },
      ],
      logScale: true,
    };
    const { page, log } = await openStats("io", "", false, io);
    await page.waitForSelector(".chart svg .series-bars.s0 rect");
    await page.waitForSelector(".chart svg .series-line.s1");
    assert.equal(await page.isChecked("#io-log"), true);
    assert.equal(await page.inputValue("input[aria-label='Field of graph 2']"), "frame.len");
    assert.deepEqual(log.find((m) => m.type === "query").params.series, [
      { metric: "bytes", filter: "tcp", field: "" },
      { metric: "max", filter: "", field: "frame.len" },
    ]);
  });

  test("expert information: severity and go to packet", async () => {
    const { page, log } = await openStats("expert");
    await page.waitForSelector("table.stats tbody tr");
    assert.ok(await page.$(".sev.sev-Chat"));
    await page.click("table.stats tbody tr:has-text('Connection finish (FIN)')");
    await page.click("button:has-text('Go to Packet')");
    assert.deepEqual(
      log.find((m) => m.type === "goto"),
      { type: "goto", frame: 18 },
    );
    await page.click("button:has-text('Prepare as Filter')");
    assert.deepEqual(
      log.find((m) => m.type === "filter"),
      { type: "filter", expr: '_ws.expert.message == "Connection finish (FIN)"', apply: false },
    );
  });

  test("expert information: Ask Copilot… sends the selected row (or none) to the host", async () => {
    const hidden = await openStats("expert");
    await hidden.page.waitForSelector("table.stats tbody tr");
    assert.equal(await hidden.page.$("#ask-copilot"), null, "no AI help: no button");

    const { page, log } = await openStats("expert", "", true);
    await page.waitForSelector("table.stats tbody tr");
    await page.click("#ask-copilot");
    for (let i = 0; i < 50 && !log.some((m) => m.type === "askCopilot"); i++) {
      await page.waitForTimeout(20);
    }
    assert.deepEqual(
      log.find((m) => m.type === "askCopilot"),
      { type: "askCopilot", rows: [] },
      "nothing selected: the capture's errors and warnings",
    );
    await page.click("table.stats tbody tr:has-text('Connection finish (FIN)')");
    await page.click("#ask-copilot");
    for (let i = 0; i < 50 && log.filter((m) => m.type === "askCopilot").length < 2; i++) {
      await page.waitForTimeout(20);
    }
    const ask = log.filter((m) => m.type === "askCopilot")[1];
    assert.equal(ask.rows.length, 1);
    assert.deepEqual(ask.rows[0], {
      severity: "Chat",
      group: "Sequence",
      protocol: "TCP",
      summary: "Connection finish (FIN)",
      count: ask.rows[0].count,
      frames: ask.rows[0].frames,
    });
    assert.ok(ask.rows[0].count >= 1 && ask.rows[0].frames.includes(18));
  });

  test("capture file properties", async () => {
    const { page } = await openStats("properties");
    await page.waitForSelector("table.stats tbody tr");
    const props = Object.fromEntries((await rows(page)).map((r) => [r[0], r[1]]));
    assert.equal(props["Number of packets"], "26");
    assert.equal(await page.$("input[type=checkbox]"), null); // no filter limit for file properties
  });

  test("HTTP statistics: a tree in its own order, report switch, row filters", async () => {
    const { page, log } = await openStats("http");
    await page.waitForSelector("table.stats tbody tr");
    assert.equal(await page.textContent(".panel-title"), "HTTP Packet Counter");
    const names = (await rows(page)).map((r) => r[0]);
    assert.equal(names[0], "Total HTTP Packets");
    assert.ok(names.includes("200 OK") && names.includes("GET"), names.join(", "));
    // Trees can't be re-sorted: headers aren't sortable.
    assert.equal(await page.$("th[aria-sort]"), null);
    const indent = (name) =>
      page.$eval(`table.stats tbody tr:has(td:text-is('${name}')) td`, (td) =>
        parseFloat(getComputedStyle(td).paddingLeft),
      );
    assert.equal((await indent("200 OK")) - (await indent("2xx: Success")), 16);

    await page.click("table.stats tbody tr:has(td:text-is('200 OK'))");
    await page.click("button:has-text('Apply as Filter')");
    assert.equal(log.find((m) => m.type === "filter").expr, "http.response.code == 200");

    await page.selectOption("#stats-type", "requests");
    await page.waitForFunction(
      () => document.querySelector(".panel-title").textContent === "HTTP Requests",
    );
    await page.dblclick("table.stats tbody tr:has(td:text-is('/index.html'))");
    assert.equal(
      log.filter((m) => m.type === "filter").at(-1).expr,
      'http.host == "example.com" && http.request.uri == "/index.html"',
    );
  });

  test("DNS and packet length statistics", async () => {
    const dns = await openStats("dns");
    await dns.page.waitForSelector("table.stats tbody tr");
    const dnsRows = Object.fromEntries((await rows(dns.page)).map((r) => [r[0], r]));
    assert.equal(dnsRows["No such name"][1], "1");
    // Average/Min/Max stay: DNS has value rows (payload size, response time).
    assert.ok(await dns.page.$("th:text-is('Average')"));

    const plen = await openStats("plen");
    await plen.page.waitForSelector("table.stats tbody tr");
    const buckets = Object.fromEntries((await rows(plen.page)).map((r) => [r[0], r[1]]));
    assert.equal(buckets["Packet Lengths"], "26");
    assert.equal(buckets["40-79"], "21");
    await plen.page.dblclick("table.stats tbody tr:has(td:text-is('40-79'))");
    assert.equal(
      plen.log.find((m) => m.type === "filter").expr,
      "frame.len >= 40 && frame.len <= 79",
    );
  });

  test("service response time: picks a protocol with traffic, marks it, switches", async () => {
    const { page, log } = await openStats("srt");
    await page.waitForFunction(
      () => document.querySelector(".panel-title").textContent === "ICMP Service Response Time",
    );
    assert.equal(await page.inputValue("#stats-type"), "icmp");
    assert.equal(await page.textContent("#stats-type option[value=icmp]"), "ICMP ●");
    assert.equal(await page.textContent("#stats-type option[value=snmp]"), "SNMP");
    const [row] = await rows(page);
    assert.deepEqual(row.slice(0, 3), ["1", "1", "0"]); // requests, replies, lost

    await page.click("table.stats tbody tr >> nth=0");
    await page.click("button:has-text('Go to Packet')");
    assert.equal(log.find((m) => m.type === "goto").frame, 3);

    await page.selectOption("#stats-type", "snmp");
    await page.waitForFunction(
      () => document.querySelector(".panel-title").textContent === "SNMP Service Response Time",
    );
    assert.equal((await rows(page)).length, 0);
    assert.equal(await page.inputValue("#stats-type"), "snmp");
  });

  test("follow TCP stream: directions, formats, stepping, filter and save", async () => {
    const { page, problems, post } = await newPage(browser);
    pages.push(problems);
    const log = [];
    let target = { frame: 14 };
    const load = () =>
      client.request("follow_stream", { proto: "tcp", ...target }, { timeoutMs: 0 }).then(
        (result) => post({ type: "result", result, label: "TCP" }),
        (err) => post({ type: "error", message: err.message }),
      );
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await load();
      } else if (msg.type === "stream") {
        target = { stream: msg.stream };
        await load();
      }
    });
    await page.setContent(renderPanelHtml(origin, "follow.js"), { waitUntil: "load" });
    await page.waitForSelector("pre.segment");
    assert.equal(await page.textContent(".panel-title"), "TCP stream 0");
    assert.match(
      await page.textContent(".follow-legend"),
      /192\.168\.1\.10:50000 → 93\.184\.216\.34:80/,
    );
    assert.ok(
      (await page.textContent("pre.segment.dir0")).startsWith(
        "GET /index.html HTTP/1.1\nHost: example.com",
      ),
    );
    assert.ok(
      (await page.textContent("pre.segment.dir1")).startsWith(
        "HTTP/1.1 200 OK\nContent-Type: text/html",
      ),
    );

    // Search: matches highlighted, Enter / Shift+Enter step through them, Esc clears.
    await page.fill("#follow-find", "html");
    await page.waitForFunction(() =>
      /^1 of \d+$/.test(document.querySelector("#follow-find-count").textContent),
    );
    const total = Number((await page.textContent("#follow-find-count")).split(" of ")[1]);
    assert.ok(total >= 2, "index.html and text/html at least");
    assert.equal(await page.locator("mark.find-match").count(), total);
    assert.equal(await page.textContent("mark.find-match.current"), "html");
    await page.press("#follow-find", "Enter");
    assert.equal(await page.textContent("#follow-find-count"), `2 of ${total}`);
    await page.press("#follow-find", "Shift+Enter");
    await page.press("#follow-find", "Shift+Enter");
    assert.equal(await page.textContent("#follow-find-count"), `${total} of ${total}`, "wraps");
    assert.ok(
      (await page.textContent("pre.segment.dir0")).startsWith("GET /index.html HTTP/1.1"),
      "the text around the matches is intact",
    );
    await page.fill("#follow-find", "no such text");
    await page.waitForFunction(
      () => document.querySelector("#follow-find-count").textContent === "No matches",
    );
    await page.press("#follow-find", "Escape");
    await page.waitForFunction(() => !document.querySelector("mark.find-match"));
    assert.equal(await page.textContent("#follow-find-count"), "");
    await page.fill("#follow-find", "HTTP/1.1"); // (left on for the accessibility check)

    await page.selectOption("select[aria-label='Direction']", "1");
    assert.equal(await page.locator("pre.segment.dir0").count(), 0);
    await page.selectOption("select[aria-label='Show data as']", "hex");
    assert.ok(
      (await page.textContent("pre.segment")).startsWith("00000000  48 54 54 50 2f 31 2e 31"),
    );

    await page.click("button:has-text('Save as…')");
    const saveText = log.find((m) => m.type === "save");
    assert.equal(saveText.dir, 1);
    assert.equal(saveText.format, "text");
    assert.ok(saveText.text.startsWith("00000000  48 54 54 50"));
    await page.selectOption("select[aria-label='Show data as']", "raw");
    await page.click("button:has-text('Save as…')");
    assert.deepEqual(log.filter((m) => m.type === "save").at(-1), {
      type: "save",
      dir: 1,
      format: "raw",
    });

    await page.click("button:has-text('Filter to Stream')");
    assert.deepEqual(
      log.find((m) => m.type === "filter"),
      { type: "filter", expr: "tcp.stream eq 0", apply: true },
    );
    await page.click("button:has-text('Filter Out This Stream')");
    assert.deepEqual(
      log.find((m) => m.type === "filterOut"),
      {
        type: "filterOut",
        expr: "tcp.stream eq 0",
      },
    );

    // There is only one TCP stream in the capture: the next one is empty.
    await page.click("button[title='Next stream']");
    await page.waitForFunction(
      () => document.querySelector(".panel-title").textContent === "TCP stream 1",
    );
    assert.equal(await page.textContent(".status"), "No payload in this stream.");
    assert.equal(await page.locator("pre.segment").count(), 0);
  });

  test("follow HTTP/2 and QUIC: sub-streams, more views, filter and save", async () => {
    // A backend of its own on the streams capture (HTTP/2, WebSocket, QUIC).
    const streams = await startBackend(deps);
    try {
      await streams.request(
        "open",
        { path: path.join(FIXTURES, "streams.pcapng") },
        { timeoutMs: 0 },
      );
      /** follow.js with a stand-in for FollowPanel, following `proto`. */
      const openFollow = async (proto, label, first) => {
        const { page, problems, post } = await newPage(browser);
        pages.push(problems);
        const log = [];
        let target = first;
        const load = () =>
          streams.request("follow_stream", { proto, ...target }, { timeoutMs: 0 }).then(
            (result) => post({ type: "result", result, label }),
            (err) => post({ type: "error", message: err.message }),
          );
        await page.exposeFunction("__toHost", async (raw) => {
          const msg = JSON.parse(raw);
          log.push(msg);
          if (msg.type === "ready") {
            await load();
          } else if (msg.type === "stream") {
            target = { stream: msg.stream, substream: msg.substream };
            await load();
          }
        });
        await page.setContent(renderPanelHtml(origin, "follow.js"), { waitUntil: "load" });
        await page.waitForSelector("pre.segment");
        return { page, log };
      };
      const title = (page, text) =>
        page.waitForFunction((t) => document.querySelector(".panel-title").textContent === t, text);
      const options = (page) =>
        page.$$eval("#follow-substream option", (o) => o.map((x) => x.textContent));

      // HTTP/2 from packet 12: its sub-stream 3, then sub-stream 1 from the picker.
      const h2 = await openFollow("http2", "HTTP/2", { frame: 12 });
      await title(h2.page, "HTTP/2 stream 0, sub-stream 3");
      assert.deepEqual(await options(h2.page), ["0 (connection)", "1", "3"]);
      assert.equal(await h2.page.inputValue("#follow-substream"), "3");
      assert.match(await h2.page.textContent("pre.segment.dir1"), /second stream body/);
      await h2.page.selectOption("#follow-substream", "1");
      await expectLast(h2.log, { type: "stream", stream: 0, substream: 1 });
      await title(h2.page, "HTTP/2 stream 0, sub-stream 1");
      assert.match(await h2.page.textContent("pre.segment.dir1"), /first stream body/);
      await h2.page.click("button:has-text('Filter to Stream')");
      await expectLast(h2.log, {
        type: "filter",
        expr: "tcp.stream eq 0 and http2.streamid eq 1",
        apply: true,
      });
      // The WebSocket conversation is TCP stream 1: no HTTP/2 there.
      await h2.page.click("button[title='Next stream']");
      await title(h2.page, "HTTP/2 stream 1, sub-stream 0");
      assert.match(await h2.page.textContent(".notice"), /No HTTP\/2 in TCP stream 1/);
      assert.ok(await h2.page.isDisabled("#follow-substream"));

      // QUIC (decrypted with the keys in the capture), then the other views.
      const q = await openFollow("quic", "QUIC", { frame: 33 });
      await title(q.page, "QUIC stream 0, sub-stream 0");
      assert.deepEqual(await options(q.page), ["0", "4"]);
      assert.equal(await q.page.textContent("pre.segment.dir0"), "GET /hello.txt\n");
      assert.equal(await q.page.textContent("pre.segment.dir1"), "Hello over QUIC!\n");
      const as = (format) => q.page.selectOption("select[aria-label='Show data as']", format);
      await as("carray");
      assert.equal(
        await q.page.textContent("pre.segment.dir0"),
        "char peer0_0[] = {\n0x47, 0x45, 0x54, 0x20, 0x2f, 0x68, 0x65, 0x6c,\n" +
          "0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x0d, 0x0a };",
      );
      await q.page.click("button:has-text('Save as…')");
      const saved = await lastOfType(q.log, "save");
      assert.equal(saved.ext, "c");
      assert.ok(saved.text.includes("char peer1_0[] = {\n0x48, 0x65"));
      await as("yaml");
      assert.equal(
        await q.page.textContent("pre.segment:not(.dir0):not(.dir1)"),
        "peers:\n  - peer: 0\n    host: '10.0.0.1'\n    port: 50300\n" +
          "  - peer: 1\n    host: '10.0.0.2'\n    port: 443\npackets:",
      );
      assert.equal(
        await q.page.textContent("pre.segment.dir0"),
        "  - peer: 0\n    index: 0\n    data: !!binary |\n      R0VUIC9oZWxsby50eHQNCg==",
      );
      await as("utf-16");
      assert.equal(await q.page.locator("pre.segment.dir0").count(), 1);
      await as("ascii");
      await q.page.selectOption("#follow-substream", "4");
      await title(q.page, "QUIC stream 0, sub-stream 4");
      assert.equal(await q.page.textContent("pre.segment.dir0"), "second stream data\n");
      assert.equal(await q.page.locator("pre.segment.dir1").count(), 0);
      await q.page.click("button:has-text('Filter Out This Stream')");
      await expectLast(q.log, {
        type: "filterOut",
        expr: "quic.connection.number eq 0 and quic.stream.stream_id eq 4",
      });
    } finally {
      await streams.dispose();
    }
  });

  /** Open coloring.js with a stand-in for ColoringPanel (src/panels/coloringPanel.ts). */
  async function openColoring(rules, defaults) {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await post({ type: "init", rules, defaults, canValidate: true });
      } else if (msg.type === "validate") {
        const res = await client.request("validate_filter", { expr: msg.filter });
        await post({
          type: "validation",
          id: msg.id,
          filter: msg.filter,
          error: res.valid ? null : res.error,
        });
      }
    });
    await page.setContent(renderPanelHtml(origin, "coloring.js"), { waitUntil: "load" });
    pages.push(problems);
    return { page, log, post };
  }

  test("coloring rules editor: edit, check filters, reorder, add, remove and save", async () => {
    const dns = {
      name: "DNS",
      filter: "dns",
      foreground: "#12272e",
      background: "#c8e2ff",
      enabled: true,
    };
    const tcp = {
      name: "TCP",
      filter: "tcp",
      foreground: "#000000",
      background: "#e7e6ff",
      enabled: true,
    };
    const arp = {
      name: "ARP",
      filter: "arp",
      foreground: "#000000",
      background: "#faf0d7",
      enabled: false,
    };
    const { page, log, post } = await openColoring([dns, tcp, arp], [dns]);
    const rowsOf = () =>
      page.$$eval("table.rules tbody tr[data-id]", (trs) =>
        trs.map((tr) => ({
          on: /** @type {HTMLInputElement} */ (tr.querySelector("input[type=checkbox]")).checked,
          name: /** @type {HTMLInputElement} */ (tr.querySelector(".rule-name")).value,
          filter: /** @type {HTMLInputElement} */ (tr.querySelector(".rule-filter")).value,
          sample: /** @type {HTMLElement} */ (tr.querySelector(".rule-sample")).style
            .backgroundColor,
        })),
      );
    await page.waitForSelector("table.rules tbody tr[data-id]");
    assert.deepEqual(await rowsOf(), [
      { on: true, name: "DNS", filter: "dns", sample: "rgb(200, 226, 255)" },
      { on: true, name: "TCP", filter: "tcp", sample: "rgb(231, 230, 255)" },
      { on: false, name: "ARP", filter: "arp", sample: "rgb(250, 240, 215)" },
    ]);
    const save = "button:has-text('Save')";
    assert.equal(await page.isDisabled(save), true, "nothing to save yet");

    // A filter tshark rejects is marked (it can still be saved: tshark skips it).
    const second = "table.rules tbody tr[data-id] >> nth=1";
    await page.fill(`${second} >> .rule-filter`, "tcp.port ==");
    await page.waitForFunction(() =>
      /\S/.test(document.querySelectorAll("table.rules .rule-problem")[1]?.textContent ?? ""),
    );
    assert.equal(await page.getAttribute(`${second} >> .rule-filter`, "aria-invalid"), "true");
    assert.equal(await page.isDisabled(save), false);
    // An empty filter can't be saved.
    await page.fill(`${second} >> .rule-filter`, "");
    assert.match(await page.textContent(`${second} >> .rule-problem`), /Enter a display filter/);
    assert.equal(await page.isDisabled(save), true);
    await page.fill(`${second} >> .rule-filter`, "tcp.port == 80");
    await page.waitForFunction(
      () => document.querySelectorAll("table.rules .rule-problem")[1]?.textContent === "",
    );

    // Add a rule on top, give it a filter and a color; move it down; remove ARP.
    await page.click("button:has-text('Add Rule')");
    await page.keyboard.type("udp");
    await page.$eval("table.rules tbody tr[data-id] input[aria-label='Row color']", (el) => {
      const input = /** @type {HTMLInputElement} */ (el);
      input.value = "#ff0000";
      input.dispatchEvent(new window.Event("input", { bubbles: true }));
    });
    await page.focus("table.rules tbody tr[data-id] >> nth=0 >> .rule-filter");
    await page.keyboard.press("Alt+ArrowDown");
    assert.equal(
      await page.evaluate(() => /** @type {HTMLInputElement} */ (document.activeElement)?.value),
      "udp",
      "focus follows the moved rule",
    );
    await page.click("table.rules tbody tr[data-id] >> nth=3 >> button[aria-label='Remove rule']");
    await page.uncheck("table.rules tbody tr[data-id] >> nth=0 >> input[type=checkbox]");
    assert.deepEqual(await rowsOf(), [
      { on: false, name: "DNS", filter: "dns", sample: "rgb(200, 226, 255)" },
      { on: true, name: "", filter: "udp", sample: "rgb(255, 0, 0)" },
      { on: true, name: "TCP", filter: "tcp.port == 80", sample: "rgb(231, 230, 255)" },
    ]);
    assert.match(await page.textContent(".status"), /3 rules, 2 enabled · unsaved changes/);

    await page.click(save);
    const saved = log.find((m) => m.type === "save");
    assert.deepEqual(saved.rules, [
      { ...dns, enabled: false },
      { name: "", filter: "udp", foreground: "#000000", background: "#ff0000", enabled: true },
      { ...tcp, filter: "tcp.port == 80" },
    ]);
    // The host answers with what the setting now holds (empty names become the filter).
    const stored = [saved.rules[0], { ...saved.rules[1], name: "udp" }, saved.rules[2]];
    await post({ type: "rules", rules: stored }); // the settings change can come first
    await post({ type: "saved", rules: stored });
    await page.waitForFunction(
      () =>
        !/unsaved|changed in settings/.test(document.querySelector(".status")?.textContent ?? ""),
    );
    assert.equal(await page.isDisabled(save), true);
    assert.equal((await rowsOf())[1].name, "udp");

    // Edited elsewhere while there are unsaved edits: say so; Revert loads them.
    await page.fill("table.rules tbody tr[data-id] >> nth=2 >> .rule-name", "Web");
    await post({ type: "rules", rules: [dns] });
    await page.waitForFunction(() =>
      /changed in settings/.test(document.querySelector(".status")?.textContent ?? ""),
    );
    await page.click("button:has-text('Restore Defaults')");
    assert.deepEqual(
      (await rowsOf()).map((r) => r.name),
      ["DNS"],
    );
    await page.click("button:has-text('Open settings.json')");
    await lastOfType(log, "openSettings");
  });

  test("export objects: list, filter, sort, go to packet and save", async () => {
    const objects = await startBackend(deps);
    try {
      await objects.request(
        "open",
        { path: path.join(FIXTURES, "objects.pcap") },
        { timeoutMs: 0 },
      );
      const { page, problems, post } = await newPage(browser);
      const log = [];
      // A stand-in for ObjectsPanel (src/panels/objectsPanel.ts).
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        log.push(msg);
        if (msg.type === "ready") {
          await post({ type: "init", title: "Export Objects · objects.pcap" });
        }
        if (msg.type === "ready" || msg.type === "list") {
          const onProgress = (p) => void post({ type: "progress", fraction: p.fraction ?? null });
          objects.request("export_objects", {}, { timeoutMs: 0, onProgress }).then(
            (res) => post({ type: "objects", objects: res.objects }),
            (err) => post({ type: "error", message: err.message, cancelled: err.code === -32800 }),
          );
        }
      });
      await page.setContent(renderPanelHtml(origin, "objects.js"), { waitUntil: "load" });
      pages.push(problems);
      await waitRows(page, 7);
      const all = await rows(page);
      assert.deepEqual(all[0], ["6", "HTTP", "example.com", "image/png", "776 B", "logo.png"]);
      assert.deepEqual(
        all.map((r) => r[5]),
        ["logo.png", "report", "upload", "dup.txt", "dup(1).txt", "config.bin", "Test report.eml"],
      );
      assert.match(await page.textContent(".status"), /^7 objects, /);
      assert.deepEqual(
        await page.$$eval("#objects-protocol option", (os) => os.map((o) => o.textContent)),
        ["All (7)", "HTTP (5)", "TFTP (1)", "IMF (1)"],
      );
      assert.ok(await page.isDisabled("#objects-save"), "nothing selected yet");

      await page.selectOption("#objects-protocol", "tftp");
      await waitRows(page, 1);
      assert.equal(await page.textContent("#objects-save-all"), "Save 1 Shown…");
      await page.selectOption("#objects-protocol", "");
      await page.fill("#objects-text", "DUP");
      await waitRows(page, 2);
      await page.fill("#objects-text", "");
      await waitRows(page, 7);

      await page.click("th:has-text('Size')"); // numeric: largest first
      assert.deepEqual((await rows(page)).map((r) => r[5]).slice(0, 3), [
        "report",
        "logo.png",
        "config.bin",
      ]);
      await page.click("th:has-text('Size')");
      assert.equal((await rows(page))[6][5], "report");

      await page.click("table.stats tbody tr:has-text('config.bin')");
      assert.ok(!(await page.isDisabled("#objects-save")));
      await page.click("#objects-save");
      await expectLast(log, { type: "save", id: 5 });
      await page.click("#objects-goto");
      await expectLast(log, { type: "goto", frame: 27 });
      await page.focus("table.stats");
      await page.keyboard.press("ArrowUp"); // (sorted by size, ascending: the mail comes before)
      await page.keyboard.press("Enter");
      await expectLast(log, { type: "goto", frame: 53 });
      await page.dblclick("table.stats tbody tr:has-text('logo.png')");
      await expectLast(log, { type: "goto", frame: 6 });
      await page.click("#objects-save-all");
      const saveAll = await lastOfType(log, "saveAll");
      assert.deepEqual([...saveAll.ids].sort(), [0, 1, 2, 3, 4, 5, 6]);
      // The row menu: right-click a row (it is selected): Go to Packet, Save…, Copy ›.
      await page.click("table.stats tbody tr:has-text('logo.png')", { button: "right" });
      assert.deepEqual(await menuLabels(page), ["Go to Packet 6", "Save…", "Copy"]);
      await pickMenu(page, "Copy", "File Name");
      await expectLast(log, { type: "copy", text: "logo.png" });

      await page.click("button:has-text('Refresh')");
      await page.waitForFunction(() =>
        /^7 objects/.test(document.querySelector(".status")?.textContent ?? ""),
      );
    } finally {
      await objects.dispose();
    }
  });

  /** Open a panel script with a stand-in host that forwards `method` to the backend. */
  async function openGraphPanel(script, onMessage) {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      await onMessage(msg, post);
    });
    await page.setContent(renderPanelHtml(origin, script), { waitUntil: "load" });
    pages.push(problems);
    return { page, log, post };
  }

  test("flow graph: endpoints, arrows, go to packet, follows the filter", async () => {
    let filter = "";
    const { page, log, post } = await openGraphPanel("flowgraph.js", async (msg, reply) => {
      // A stand-in for FlowGraphPanel (src/panels/flowGraphPanel.ts).
      if (msg.type === "ready") {
        await reply({ type: "init", title: "Flow Graph · mixed.pcapng", filter });
      } else if (msg.type === "query") {
        const params = { offset: msg.offset, limit: msg.limit };
        client.request("flow_graph", params, { timeoutMs: 0 }).then(
          (pageData) => reply({ type: "page", id: msg.id, offset: msg.offset, page: pageData }),
          (err) => reply({ type: "error", id: msg.id, message: err.message }),
        );
      }
    });
    await page.waitForFunction(() => document.querySelectorAll(".flow-row").length === 26);
    const nodes = await page.$$eval(".flow-node", (els) => els.map((e) => e.textContent));
    assert.deepEqual(nodes.slice(0, 3), ["02:00:00:00:00:01", "Broadcast", "192.168.1.10"]);
    assert.equal(nodes.length, 8);
    assert.match(
      await page.textContent(".status, .toolbar span"),
      /26 packets between 8 endpoints/,
    );
    const label = await page.textContent(".flow-row:nth-of-type(1) .flow-label");
    assert.match(label, /^ARP: Who has 192\.168\.1\.1\?/);
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS ? `${process.env.PCAP_SCREENSHOTS}/flow.png` : undefined,
    });

    await page.click(".flow-row:nth-of-type(4)");
    await expectLast(log, { type: "goto", frame: 4 });
    await page.focus(".flow-scroll");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await expectLast(log, { type: "goto", frame: 5 });

    // The capture's filter changes: the graph follows it.
    await client.request("set_filter", { expr: "dns" });
    filter = "dns";
    await post({ type: "reset", filter });
    await page.waitForFunction(() => document.querySelectorAll(".flow-row").length === 6);
    assert.equal((await page.$$(".flow-node")).length, 2);
    assert.match(await page.textContent(".toolbar span"), /6 packets matching dns between 2/);
    await client.request("set_filter", { expr: "" });
  });

  test("TCP stream graph: the four graphs, direction, stepping, go to packet", async () => {
    const { page, log } = await openGraphPanel("tcpgraph.js", async (msg, reply) => {
      // A stand-in for TcpGraphPanel (src/panels/tcpGraphPanel.ts).
      if (msg.type === "ready") {
        await reply({ type: "init", frame: 14, ai: true });
      } else if (msg.type === "query") {
        const params = msg.stream !== undefined ? { stream: msg.stream } : { frame: msg.frame };
        client.request("tcp_graph", params, { timeoutMs: 0 }).then(
          (result) => reply({ type: "stream", id: msg.id, result }),
          (err) => reply({ type: "error", id: msg.id, message: err.message }),
        );
      }
    });
    // mixed.pcapng: an HTTP exchange; the server sends the most data, so it's shown first.
    await page.waitForFunction(() =>
      /^TCP stream 0: 93\.184\.216\.34:80 → 192\.168\.1\.10:50000$/.test(
        document.querySelector(".panel-title").textContent,
      ),
    );
    assert.ok(
      (await page.$$(".chart line.seg")).length >= 1,
      "Stevens: one segment per data packet",
    );
    assert.match(await page.textContent(".status"), /data segments/);
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS
        ? `${process.env.PCAP_SCREENSHOTS}/tcp-stevens.png`
        : undefined,
    });

    for (const [kind, selector] of [
      ["throughput", ".chart path.series-line"],
      ["rtt", ".chart circle.dot"],
      ["window", ".chart path.series-line"],
    ]) {
      await page.selectOption("select", kind);
      await page.waitForSelector(selector, { state: "attached" }); // (a flat line has no height)
    }
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS
        ? `${process.env.PCAP_SCREENSHOTS}/tcp-window.png`
        : undefined,
    });

    await page.selectOption("select", "stevens");
    await page.click("#tcp-direction");
    assert.match(await page.textContent(".panel-title"), /192\.168\.1\.10:50000 → 93\.184/);

    const box = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForFunction(() =>
      /^Packet \d+/.test(document.querySelector(".chart .tooltip").textContent),
    );
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await lastOfType(log, "goto");

    // Ask Copilot… posts the stream shown; the host runs the request.
    await page.click("#tcp-ask");
    await expectLast(log, { type: "askCopilot", stream: 0 });

    await page.click("button[title='Next stream']");
    await page.waitForFunction(() =>
      /^TCP stream 1/.test(document.querySelector(".panel-title").textContent),
    );
    assert.match(await page.textContent(".status"), /No packets in this stream/);
  });

  test("compare packets: fields side by side, differences marked, only differences, swap", async () => {
    let frames = [4, 6];
    const { page, log } = await openGraphPanel("compare.js", async (msg, reply) => {
      // A stand-in for ComparePanel (src/panels/comparePanel.ts).
      if (msg.type === "swap") {
        frames = [frames[1], frames[0]];
      }
      if (msg.type === "ready" || msg.type === "swap") {
        await reply({ type: "loading", frames });
        const [a, b] = await Promise.all(
          frames.map((number) => client.request("packet_detail", { number }, { timeoutMs: 0 })),
        );
        await reply({ type: "show", a, b });
      }
    });
    // mixed.pcapng: frames 4 and 6 are DNS queries for example.com and wireshark.org.
    await page.waitForFunction(() =>
      /^Compare Packets 4 and 6$/.test(document.querySelector(".panel-title").textContent),
    );
    assert.match(
      await page.textContent(".status"),
      /^\d+ fields differ · 0 only in packet 4 · 0 only in packet 6$/,
    );
    const cells = () =>
      page.$$eval("table.compare tbody tr", (trs) =>
        trs.map((tr) => [tr.className, tr.children[1].textContent, tr.children[2].textContent]),
      );
    let shown = await cells();
    // Only differences (the default): every row differs or holds one that does.
    assert.ok(
      shown.some(
        ([cls, a, b]) =>
          cls === "cmp-changed" &&
          a === "example.com: type A, class IN" &&
          b === "wireshark.org: type A, class IN",
      ),
    );
    assert.ok(!shown.some(([, a]) => /^Type: IPv4/.test(a)), "Ethernet's type is the same in both");
    assert.ok(
      shown.some(([cls]) => /cmp-proto/.test(cls)),
      "protocols stay as headings",
    );
    assert.equal(
      await page.$eval(
        "table.compare tr.cmp-changed .cmp-mark .visually-hidden",
        (s) => s.textContent,
      ),
      "Differs",
    );
    await page.click("#cmp-only");
    shown = await cells();
    assert.ok(shown.some(([cls, a]) => cls === "cmp-same" && /^Type: IPv4/.test(a)));
    await page.click("#cmp-swap");
    await page.waitForFunction(() =>
      /^Compare Packets 6 and 4$/.test(document.querySelector(".panel-title").textContent),
    );
    await page.click("#cmp-goto-a");
    await expectLast(log, { type: "goto", frame: 6 });
  });

  test("VoIP calls: calls, call flow, streams, analysis, audio, filters", async () => {
    const voip = await startBackend(deps);
    try {
      await voip.request("open", { path: path.join(FIXTURES, "voip.pcap") }, { timeoutMs: 0 });
      const { page, problems, post } = await newPage(browser);
      const log = [];
      let played = 0;
      // A stand-in for VoipPanel (src/panels/voipPanel.ts).
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        log.push(msg);
        const reply = (method, params, ok) =>
          voip.request(method, params, { timeoutMs: 0 }).then(ok, (err) =>
            post({
              type: "error",
              id: msg.id,
              message: err.message,
              unsupported: !!err.data?.unsupported,
            }),
          );
        if (msg.type === "ready") {
          await post({ type: "init", title: "VoIP Calls · voip.pcap" });
        } else if (msg.type === "list") {
          await reply("voip_calls", { heuristic: msg.heuristic }, (r) =>
            post({ type: "calls", ...r, heuristic: msg.heuristic }),
          );
        } else if (msg.type === "analyse") {
          await reply("rtp_stream", { stream: msg.stream }, (result) =>
            post({ type: "analysis", id: msg.id, result }),
          );
        } else if (msg.type === "play") {
          const name = `stream-${++played}.wav`;
          await reply("rtp_audio", { stream: msg.stream, dest: path.join(media, name) }, (r) =>
            post({ type: "audio", id: msg.id, uri: `${origin}/media/${name}`, ...r }),
          );
        } else if (msg.type === "playCall") {
          const name = `call-${++played}.wav`;
          await reply("call_audio", { streams: msg.streams, dest: path.join(media, name) }, (r) =>
            post({
              type: "callAudio",
              id: msg.id,
              call: msg.call,
              uri: `${origin}/media/${name}`,
              ...r,
            }),
          );
        }
      });
      await page.setContent(renderPanelHtml(origin, "voip.js", { media: true }), {
        waitUntil: "load",
      });
      pages.push(problems);
      const cells = (table) =>
        page.$$eval(`${table} tbody tr`, (trs) =>
          trs.map((tr) => [...tr.children].map((td) => td.textContent)),
        );
      const waitLog = async (type) => {
        for (let i = 0; i < 100 && !log.some((m) => m.type === type); i++) {
          await page.waitForTimeout(20);
        }
        return log.filter((m) => m.type === type).at(-1);
      };

      await page.waitForFunction(
        () => document.querySelectorAll("#voip-calls tbody tr").length === 2,
      );
      assert.equal(await page.textContent(".panel-title"), "VoIP Calls · voip.pcap");
      assert.match(await page.textContent(".status"), /^2 calls, 2 streams$/);
      const [call, busy] = await cells("#voip-calls");
      assert.deepEqual(call.slice(1, 5), ["SIP", "alice@10.0.0.1", "bob@10.0.0.2", "Completed"]);
      assert.equal(call[6], "0:01", "answered for about a second");
      assert.deepEqual(busy.slice(4, 8), ["Rejected (486 Busy Here)", "", "", "0"]);
      assert.deepEqual(call.slice(9), ["4.23 (High)", ""], "MOS of the worst stream, no problems");

      // The selected call's details: timings, how it ended, quality.
      assert.equal(
        await page.textContent("#voip-call-facts"),
        "Rang after 0.050 s · answered after 1.000 s · lasted 0:01 · final response 200 OK · " +
          "ended by the caller (10.0.0.1)",
      );
      assert.match(
        await page.textContent("#voip-call-quality"),
        /^MOS 4\.23 \(High, R 85\.9\) for 10\.0\.0\.1:40000 → 10\.0\.0\.2:50000/,
      );
      assert.match(await page.textContent("#voip-call-details"), /No media problems found\./);
      assert.equal(await page.$("#voip-dtmf"), null, "no DTMF in this call");
      // The whole call: caller left, callee right, a waveform with a playhead; a click seeks.
      assert.ok(await page.$eval("#voip-ask", (b) => b.classList.contains("hidden")), "no AI");
      await page.click("#voip-play-call");
      await page.waitForFunction(() => {
        const a = /** @type {HTMLAudioElement} */ (document.querySelector("#voip-call-audio"));
        return a.readyState >= 1 && a.duration > 0;
      });
      assert.ok(Math.abs((await page.$eval("#voip-call-audio", (a) => a.duration)) - 1) < 0.01);
      assert.equal(
        await page.textContent("#voip-call-audio-note"),
        "G.711 µ-law, 1.0 s, caller left, callee right",
      );
      assert.equal((await page.$$("#voip-waveform path.wave")).length, 2);
      assert.match(
        await page.getAttribute("#voip-waveform svg", "aria-label"),
        /^Waveform: Caller alice@10\.0\.0\.1, Callee bob@10\.0\.0\.2\./,
      );
      const playCallMsg = await waitLog("playCall");
      assert.deepEqual(playCallMsg.streams.map((st) => [st.srcPort, st.channel]).sort(), [
        [40000, 0],
        [50000, 1],
      ]);
      await page.evaluate(() =>
        /** @type {HTMLAudioElement} */ (document.querySelector("#voip-call-audio")).pause(),
      );
      const box = await page.$eval("#voip-waveform", (w) => {
        const r = w.getBoundingClientRect();
        return { x: r.x, y: r.y, width: r.width, height: r.height };
      });
      await page.mouse.click(box.x + box.width * 0.75, box.y + box.height / 2);
      const seeked = await page.$eval("#voip-call-audio", (a) => a.currentTime);
      assert.ok(Math.abs(seeked - 0.75) < 0.05, `seeked to ${seeked}`);
      await page.waitForFunction(
        () =>
          Math.abs(
            parseFloat(
              document.querySelector("#voip-waveform .playhead")?.getAttribute("x1") ?? "0",
            ) - 75,
          ) < 5,
      );
      await page.click("#voip-save-call-audio");
      assert.equal((await waitLog("saveCallAudio")).streams.length, 2);
      await page.click("#voip-save-call");
      assert.deepEqual((await waitLog("saveCall")).call.id, 0);
      assert.match(
        (await waitLog("saveCall")).call.filter,
        /^sip\.Call-ID == "call-1@10\.0\.0\.1"/,
      );

      // The first call is selected: its flow (7 SIP messages + 2 RTP streams) and its streams.
      assert.equal((await page.$$("#voip-flow .flow-row")).length, 9);
      assert.equal((await page.$$("#voip-flow .flow-row.voip-rtp")).length, 2);
      assert.deepEqual(
        await page.$$eval("#voip-flow .voip-node", (n) => n.map((t) => t.textContent)),
        ["10.0.0.1", "10.0.0.2"],
      );
      assert.equal((await page.$$("#voip-streams tbody tr.linked")).length, 2);
      await page.click("#voip-flow .flow-row >> nth=0");
      assert.deepEqual(await waitLog("goto"), { type: "goto", frame: 1 });
      await page.click("#voip-filter-call");
      assert.match(
        (await waitLog("filter")).expr,
        /^sip\.Call-ID == "call-1@10\.0\.0\.1" \|\| \(rtp\.ssrc/,
      );

      // An RTP row of the flow selects its stream.
      const streams = await cells("#voip-streams");
      const alice = streams.findIndex((r) => r[0] === "10.0.0.1:40000");
      assert.deepEqual(streams[alice].slice(3, 6), ["g711U", "49", "1 (2.0%)"]);
      assert.deepEqual(streams[alice].slice(9), ["", "4.23 (High)", "", "⚠"]);
      assert.ok(await page.$eval("#voip-analyse", (b) => b.disabled), "no stream selected yet");
      await page.click("#voip-flow .flow-row.voip-rtp:has-text('1 lost')");
      await page.waitForSelector(`#voip-streams tbody tr:nth-child(${alice + 1}).selected`);
      assert.equal(await page.textContent("#voip-rtcp"), "No RTCP reports about this stream.");

      await page.click("#voip-analyse");
      await page.waitForSelector("#voip-summary");
      const summary = await page.textContent("#voip-summary");
      assert.match(summary, /^49 of 50 packets · 1 lost \(2\.0%\) · max delta 42\.3\d\d ms/);
      assert.ok(await page.$("#voip-analysis .chart path.series-line"), "the jitter line");
      assert.equal((await page.$$("#voip-analysis circle.dot.retrans")).length, 1);
      assert.deepEqual(
        await page.$$eval("#voip-problems li", (li) => li.map((l) => l.textContent)),
        ["Packet 48: 1 packet lost before seq 1021"],
      );
      await page.click("#voip-problems button");
      assert.equal((await waitLog("goto")).frame, 48);

      // Play: the backend writes a WAV into the panel's folder; the <audio> element loads it.
      await page.click("#voip-play");
      await page.waitForFunction(() => {
        const a = document.querySelector("#voip-audio");
        return a && !a.classList.contains("hidden") && a.readyState >= 1;
      });
      assert.ok(Math.abs((await page.$eval("#voip-audio", (a) => a.duration)) - 1) < 0.01);
      assert.equal(
        await page.textContent("#voip-audio-note"),
        "G.711 µ-law, 1.0 s, 0.02 s of silence for lost packets",
      );

      await page.click("#voip-save");
      assert.equal((await waitLog("save")).format, "wav");
      await page.click("#voip-filter-stream");
      assert.match(
        log.filter((m) => m.type === "filter").at(-1).expr,
        /^rtp\.ssrc == 0x11111111 && ip\.src == 10\.0\.0\.1/,
      );

      // The rejected call: no media; keyboard selection.
      await page.focus("#voip-calls tbody tr >> nth=0");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
      await page.waitForFunction(
        () => document.querySelectorAll("#voip-flow .flow-row").length === 4,
      );
      assert.equal((await page.$$("#voip-streams tbody tr.linked")).length, 0);
      assert.match(
        await page.textContent("#voip-call-facts"),
        /^Not answered · final response 486 Busy Here · ended by the callee \(10\.0\.0\.2\)$/,
      );
      assert.match(await page.textContent("#voip-call-details"), /Not answered: no media expected/);

      // Row menus: the toolbar's actions that can act now, then Copy ›.
      await page.click("#voip-calls tbody tr >> nth=0", { button: "right" });
      await page.waitForSelector("#context-menu:not(.hidden)");
      const callMenu = await menuLabels(page);
      assert.deepEqual(callMenu.slice(0, 2), ["Filter Call", "Save Call…"]);
      assert.equal(callMenu.at(-1), "Copy");
      await pickMenu(page, "Filter Call");
      assert.equal((await lastOfType(log, "filter")).type, "filter");
      await page.click("#voip-streams tbody tr >> nth=0", { button: "right" });
      assert.deepEqual((await menuLabels(page)).slice(0, 2), ["Analyse", "Play"]);
      await pickMenu(page, "Copy", "Row");
      assert.match((await lastOfType(log, "copy")).text, /^10\.0\.0\.1:40000\t/);

      await page.check("#voip-heuristic");
      assert.equal(
        (await waitLog("list")) && log.filter((m) => m.type === "list").at(-1).heuristic,
        true,
      );
      await page.screenshot({
        path: process.env.PCAP_SCREENSHOTS ? `${process.env.PCAP_SCREENSHOTS}/voip.png` : undefined,
      });
    } finally {
      await voip.dispose();
    }
  });

  test("VoIP call details: DTMF digits and media problems link to their packets", async () => {
    const voip = await startBackend(deps);
    try {
      await voip.request(
        "open",
        { path: path.join(FIXTURES, "voip-calls.pcap") },
        { timeoutMs: 0 },
      );
      const { page, problems, post } = await newPage(browser);
      const log = [];
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        log.push(msg);
        if (msg.type === "ready") {
          await post({ type: "init", title: "VoIP Calls · voip-calls.pcap", ai: true });
        } else if (msg.type === "list") {
          const r = await voip.request("voip_calls", { heuristic: false }, { timeoutMs: 0 });
          await post({ type: "calls", ...r, heuristic: false });
        }
      });
      await page.setContent(renderPanelHtml(origin, "voip.js", { media: true }), {
        waitUntil: "load",
      });
      pages.push(problems);
      await page.waitForFunction(
        () => document.querySelectorAll("#voip-calls tbody tr").length === 5,
      );
      const calls = await page.$$eval("#voip-calls tbody tr", (trs) =>
        trs.map((tr) => [...tr.children].slice(9).map((td) => td.textContent)),
      );
      assert.deepEqual(calls, [
        ["4.40 (Best)", ""],
        ["4.40 (Best)", "⚠ 4"],
        ["", "⚠ 1"],
        ["", ""],
        ["", ""],
      ]);

      // Call 1: DTMF from both sides, the callee hung up with a Q.850 cause.
      assert.match(
        await page.textContent("#voip-call-facts"),
        / · ended by the callee \(10\.0\.1\.2\) · Reason: Q\.850 cause 16: Normal call clearing$/,
      );
      assert.equal(await page.textContent("#voip-call-details h3"), "DTMF: 4 7 #");
      assert.deepEqual(await page.$$eval("#voip-dtmf li", (li) => li.map((l) => l.textContent)), [
        "Packet 46: 4 · RFC 4733 from 10.0.1.1, 80 ms",
        "Packet 85: 7 · SIP INFO from 10.0.1.2, 250 ms",
        "Packet 128: # · RFC 4733 from 10.0.1.1, 80 ms",
      ]);
      await page.click("#voip-dtmf button >> nth=1");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 85 });
      const streamDtmf = await page.$$eval("#voip-streams tbody tr", (trs) =>
        trs.map((tr) => tr.children[11].textContent),
      );
      assert.ok(streamDtmf.includes("4 #"), "the caller's stream lists its RFC 4733 digits");

      // Call 2: four media problems, each a link to its packet.
      await page.click("#voip-calls tbody tr >> nth=1");
      await page.waitForSelector("#voip-call-problems");
      const listed = await page.$$eval("#voip-call-problems li", (li) =>
        li.map((l) => l.textContent),
      );
      assert.equal(listed.length, 4);
      assert.match(listed[0], /^Packet \d+: One-way audio: only the caller sends RTP/);
      assert.match(listed[1], /sends PCMA \(8\), but the SDP answer agreed on PCMU \(0\)$/);
      assert.match(listed[2], /changed SSRC from 0x33333333 to 0x44444444/);
      assert.equal(
        listed[3],
        "Packet 225: No RTP from 10.0.1.3:34000 for 1.52 s before packet 225",
      );
      await page.click("#voip-call-problems li >> nth=3 >> button");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 225 });

      // Call 3: answered, no RTP; no quality to show.
      await page.click("#voip-calls tbody tr >> nth=2");
      await page.waitForFunction(() =>
        document.querySelector("#voip-call-problems")?.textContent?.includes("No RTP after"),
      );
      assert.equal(await page.textContent("#voip-call-quality"), "No media to rate.");

      // Ask Copilot (AI help available) sends the selected call, by index.
      await page.click("#voip-ask");
      assert.deepEqual(log.at(-1), { type: "askCopilot", call: 2 });

      // Registrations: one row per REGISTER transaction; a row goes to its last packet.
      const regs = await page.$$eval("#voip-registrations tbody tr", (trs) =>
        trs.map((tr) => [...tr.children].map((td) => td.textContent)),
      );
      assert.deepEqual(
        regs.map((r) => r.slice(1)),
        [
          [
            "dave@example.test",
            "10.0.1.1",
            "10.0.1.100",
            "Registered (1 challenge)",
            "200 OK",
            "3600",
          ],
          ["frank@example.test", "10.0.1.3", "10.0.1.100", "Failed", "403 Forbidden", "3600"],
          ["grace@example.test", "10.0.1.4", "10.0.1.100", "Unregistered", "200 OK", "0"],
        ],
      );
      await page.click("#voip-registrations tbody tr >> nth=1");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 287 });
    } finally {
      await voip.dispose();
    }
  });

  test("VoIP calls over H.323, MGCP and IAX2: their flows, media and details", async () => {
    const voip = await startBackend(deps);
    try {
      await voip.request(
        "open",
        { path: path.join(FIXTURES, "voip-other.pcap") },
        { timeoutMs: 0 },
      );
      const { page, problems, post } = await newPage(browser);
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        if (msg.type === "ready") {
          await post({ type: "init", title: "VoIP Calls · voip-other.pcap" });
        } else if (msg.type === "list") {
          const r = await voip.request("voip_calls", { heuristic: false }, { timeoutMs: 0 });
          await post({ type: "calls", ...r, heuristic: false });
        }
      });
      await page.setContent(renderPanelHtml(origin, "voip.js", { media: true }), {
        waitUntil: "load",
      });
      pages.push(problems);
      await page.waitForFunction(
        () => document.querySelectorAll("#voip-calls tbody tr").length === 7,
      );
      assert.match(await page.textContent(".status"), /^7 calls, 7 streams$/);
      const calls = await page.$$eval("#voip-calls tbody tr", (trs) =>
        trs.map((tr) => [...tr.children].slice(1, 5).map((td) => td.textContent)),
      );
      assert.deepEqual(calls, [
        ["H.323", "alan <1001>", "2002", "Completed"],
        ["H.323", "carl <3003>", "betty <2002>", "Completed"],
        ["H.323", "alan <1001>", "2002", "Rejected (User busy)"],
        ["IAX2", "Mike <3001>", "4001@default", "Completed"],
        ["IAX2", "3002", "9999", "Rejected (No such context/extension)"],
        ["MGCP", "aaln/1@gw1.example.net", "aaln/1@gw2.example.net", "Completed"],
        [
          "MGCP",
          "aaln/1@gw2.example.net",
          "aaln/1@gw1.example.net",
          "Rejected (401 Phone off hook)",
        ],
      ]);
      // The H.323 call: H.245 inside H.225 messages, an H.245 DTMF digit.
      assert.equal((await page.$$("#voip-flow .flow-row.voip-rtp")).length, 2);
      assert.equal(await page.textContent("#voip-call-details h3"), "DTMF: 5");

      // The IAX2 call: its voice frames are streams of their own.
      await page.click("#voip-calls tbody tr >> nth=3");
      await page.waitForFunction(
        () => document.querySelectorAll("#voip-flow .flow-row.voip-rtp").length === 2,
      );
      assert.deepEqual(
        await page.$$eval("#voip-flow .flow-row.voip-rtp text.flow-label", (t) =>
          t.map((l) => l.textContent),
        ),
        ["IAX2 voice g711U · 50 packets", "IAX2 voice g711U · 50 packets"],
      );
      const linked = await page.$$eval("#voip-streams tbody tr.linked", (trs) =>
        trs.map((tr) => tr.children[2].textContent),
      );
      assert.deepEqual(linked, ["IAX2", "IAX2"], "no SSRC");
      assert.match(
        await page.textContent("#voip-call-facts"),
        /ended by the callee \(10\.0\.3\.1\)/,
      );

      // The MGCP call: the digits dialled before it, the agent between the gateways.
      await page.click("#voip-calls tbody tr >> nth=5");
      await page.waitForFunction(() =>
        document.querySelector("#voip-call-facts")?.textContent?.startsWith("Dialled 2002"),
      );
      assert.deepEqual(
        await page.$$eval("#voip-flow .voip-node", (n) => n.map((t) => t.textContent)),
        ["10.0.4.11", "10.0.4.1", "10.0.4.12"],
      );
    } finally {
      await voip.dispose();
    }
  });

  test("credentials: who logged in, by protocol, go to packet and filter", async () => {
    const creds = await startBackend(deps);
    try {
      await creds.request(
        "open",
        { path: path.join(FIXTURES, "credentials.pcap") },
        { timeoutMs: 0 },
      );
      const { page, log } = await openGraphPanel("stats.js", async (msg, reply) => {
        // A stand-in for StatsPanel (src/panels/statsPanel.ts) on its own capture.
        if (msg.type === "ready") {
          await reply({ type: "init", kind: "credentials", title: "Credentials", filter: "" });
        } else if (msg.type === "query") {
          const table = await creds.request("stats", { kind: "credentials" }, { timeoutMs: 0 });
          await reply({ type: "result", id: msg.id, table });
        }
      });
      await waitRows(page, 4);
      assert.deepEqual(
        (await rows(page)).map((r) => r.slice(1, 3)),
        [
          ["HTTP basic auth", "alice"],
          ["FTP", "bob"],
          ["POP3", "carol"],
          ["IMAP", "dave"],
        ],
      );
      await page.click("table.stats tbody tr:has-text('bob')");
      await page.click("button:has-text('Go to Packet')");
      await page.click("button:has-text('Prepare as Filter')");
      for (let i = 0; i < 50 && !log.some((m) => m.type === "filter"); i++) {
        await page.waitForTimeout(20);
      }
      const frame = Number((await rows(page))[1][0]);
      assert.deepEqual(
        log.find((m) => m.type === "goto"),
        { type: "goto", frame },
      );
      assert.deepEqual(
        log.find((m) => m.type === "filter"),
        {
          type: "filter",
          expr: `frame.number == ${frame}`,
          apply: false,
        },
      );
    } finally {
      await creds.dispose();
    }
  });

  test("packet bytes: decode as Base64 or compressed, show as text, arrays or an image, find, save", async () => {
    const zlib = require("node:zlib");
    const hex = (/** @type {Buffer | string} */ b) => Buffer.from(b).toString("hex");
    let field = {
      frame: 7,
      field: "http.authbasic",
      label: "Credentials: SGVsbG8sIFdvcmxkIQ==",
      hex: hex("SGVsbG8sIFdvcmxkIQ=="),
    };
    const { page, log, post } = await openGraphPanel("bytes.js", async (msg, reply) => {
      // A stand-in for BytesPanel (src/panels/bytesPanel.ts).
      if (msg.type === "ready") {
        await reply({ type: "show", ...field });
      }
    });
    const text = () => page.textContent(".bytes-text");
    await page.waitForSelector(".bytes-text");
    assert.equal(await page.textContent(".panel-title"), "Packet Bytes · packet 7");
    assert.equal(await text(), "SGVsbG8sIFdvcmxkIQ==");
    await page.selectOption("select[aria-label='Decode as']", "base64");
    await page.waitForFunction(
      () => document.querySelector(".bytes-text")?.textContent === "Hello, World!",
    );
    assert.equal(await page.textContent(".status"), "13 of 13 bytes (decoded from 20)");
    // Find highlights in the text; Enter steps.
    await page.fill("#bytes-find", "o");
    await page.press("#bytes-find", "Enter");
    await page.waitForFunction(
      () => document.querySelectorAll(".bytes-text mark.find-match").length === 2,
    );
    // Start and end bytes cut what is shown (and saved).
    await page.fill("#bytes-start", "7");
    await page.fill("#bytes-end", "11");
    await page.press("#bytes-end", "Enter");
    await page.waitForFunction(
      () => document.querySelector(".bytes-text")?.textContent === "World",
    );
    await page.selectOption("select[aria-label='Show as']", "c");
    assert.equal(
      await text(),
      "static const unsigned char http_authbasic[5] = {\n    0x57, 0x6f, 0x72, 0x6c, 0x64\n};",
    );
    await page.click("button:has-text('Save Raw…')");
    await page.click("button:has-text('Save as…')");
    await page.click("button:has-text('Copy')");
    for (let i = 0; i < 50 && log.filter((m) => m.type === "save").length < 2; i++) {
      await page.waitForTimeout(20);
    }
    const saves = log.filter((m) => m.type === "save");
    assert.deepEqual(saves[0], { type: "save", base64: Buffer.from("World").toString("base64") });
    assert.equal(saves[1].ext, "c");
    assert.match(saves[1].text, /^static const unsigned char/);
    assert.match(log.find((m) => m.type === "copy")?.text ?? "", /0x57, 0x6f/);

    // A gzip body, decompressed in the panel; a field that isn't compressed says so.
    field = {
      frame: 9,
      field: "http.file_data",
      label: "File Data: 31 bytes",
      hex: hex(zlib.gzipSync("compressed text")),
    };
    await post({ type: "show", ...field });
    await page.selectOption("select[aria-label='Show as']", "ascii");
    await page.selectOption("select[aria-label='Decode as']", "compressed");
    await page.waitForFunction(
      () => document.querySelector(".bytes-text")?.textContent === "compressed text",
    );
    assert.match(await page.textContent(".status"), /gzip decompressed/);
    await post({ type: "show", frame: 9, field: "data", label: "Data", hex: hex("plain") });
    await page.waitForSelector(".notice.error:not(.hidden)");
    assert.match(
      await page.textContent(".notice.error"),
      /^Not deflate-raw data: showing the bytes as they are\.$/,
    );

    // An image is shown as one (a 1×1 PNG).
    const png =
      "89504e470d0a1a0a0000000d4948445200000001000000010806000000" +
      "1f15c4890000000d49444154789c63f8cfc0f01f0005000201a6d5eb2a0000000049454e44ae426082";
    await post({ type: "show", frame: 3, field: "png", label: "PNG", hex: png });
    await page.selectOption("select[aria-label='Decode as']", "none");
    await page.selectOption("select[aria-label='Show as']", "image");
    await page.waitForSelector(".bytes-image");
    assert.match(
      await page.getAttribute(".bytes-image", "src"),
      /^data:image\/png;base64,iVBORw0KGgo/,
    );
    await page.waitForFunction(
      () =>
        /** @type {HTMLImageElement} */ (document.querySelector(".bytes-image")).naturalWidth === 1,
    );
    await page.click("button:has-text('Go to Packet')");
    for (let i = 0; i < 50 && !log.some((m) => m.type === "goto"); i++) {
      await page.waitForTimeout(20);
    }
    assert.ok(log.some((m) => m.type === "goto"));
    await page.selectOption("select[aria-label='Show as']", "hexdump");
  });

  test("packet window: tree over bytes, field highlight, keyboard, filters", async () => {
    const { page, log, post } = await openGraphPanel("packet.js", async (msg, reply) => {
      // A stand-in for PacketPanel (src/panels/packetPanel.ts).
      if (msg.type === "ready") {
        const d = await client.request("packet_detail", { number: 4 }, { timeoutMs: 0 });
        await reply({ type: "show", title: "Packet 4", frame: 4, ...d });
      }
    });
    await page.waitForSelector(".packet-node");
    assert.equal(await page.textContent(".panel-title"), "Packet 4");
    // Top-level protocols start open; the first is selected and takes Tab.
    const top = await page.$$eval(".packet-node[aria-level='1']", (els) =>
      els.map((e) => [e.textContent, e.getAttribute("aria-expanded")]),
    );
    assert.ok(top.length >= 4 && top.every(([, open]) => open === "true"), String(top));
    assert.equal(await page.getAttribute(".packet-node.selected", "tabindex"), "0");
    // Pick the DNS query name: its bytes are highlighted, filters are offered.
    await page.click("button[aria-label='Expand all']");
    await page.click(".packet-node:text-is('Name: example.com')");
    assert.equal(await page.getAttribute(".packet-node.selected", "aria-level"), "4");
    const marked = await page.$$eval(".packet-hex .hex-ascii mark", (els) =>
      els.map((e) => e.textContent).join(""),
    );
    assert.equal(marked, ".example.com.");
    await page.click("button:has-text('Apply as Filter')");
    await expectLast(log, { type: "filter", expr: 'dns.qry.name == "example.com"', apply: true });
    await page.click("button:has-text('Copy Value')");
    await expectLast(log, { type: "copy", text: "example.com" });
    // Arrow keys: Left goes to the parent (and closes it), Right opens and enters.
    await page.focus(".packet-node.selected");
    await page.keyboard.press("ArrowLeft");
    assert.match(await page.textContent(".packet-node.selected"), /^example\.com: type A/);
    await page.keyboard.press("ArrowLeft");
    assert.equal(await page.getAttribute(".packet-node.selected", "aria-expanded"), "false");
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press("ArrowRight");
    assert.match(await page.textContent(".packet-node.selected"), /^Name: example\.com$/);
    // Collapse all leaves the top level.
    await page.click("button[aria-label='Collapse all']");
    assert.equal(await page.locator(".packet-node").count(), top.length);
    await page.click("button:has-text('Go to Packet')");
    await expectLast(log, { type: "goto", frame: 4 });

    // The file view: the file's own tree (only its first node open), no frame.
    const file = await client.request("file_format", {}, { timeoutMs: 0 });
    await post({ type: "show", title: file.format, ...file, expand: false });
    await page.waitForFunction(
      () => document.querySelector(".panel-title")?.textContent === "PCAPNG File Format",
    );
    assert.ok(await page.isHidden("button:has-text('Go to Packet')"));
    assert.match(
      await page.textContent(".packet-node[aria-level='2']"),
      /^Block 1: Section Header Block/,
    );
    assert.match(await page.textContent(".hex-row .hex-bytes"), /^0a 0d 0d 0a/);
  });

  test("replay to service: targets, destinations, presets, replay, errors and stop", async () => {
    // (The captures list is a table.stats too: these count the targets' rows.)
    const rows = (page) =>
      page.$$eval("table.replay tbody tr", (trs) =>
        trs.map((tr) => [...tr.children].map((td) => td.textContent)),
      );
    const waitRows = (page, n) =>
      page.waitForFunction(
        (count) => document.querySelectorAll("table.replay tbody tr").length === count,
        n,
      );
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-replay-"));
    const later = path.join(tmp, "later.pcap"); // another capture of the same delivery
    fs.copyFileSync(path.join(FIXTURES, "replay.pcap"), later);
    const net = require("node:net");
    const dgram = require("node:dgram");
    /** A TCP server keeping what each connection sent (a stand-in collector). */
    const collector = async () => {
      const got = [];
      const server = net.createServer((sock) => {
        const chunks = [];
        got.push(chunks);
        sock.on("data", (d) => chunks.push(d));
        sock.on("error", () => {}); // (the recorded reset)
      });
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      return { server, got, port: server.address().port };
    };
    const hi2 = await collector();
    const hi3 = await collector();
    const udp = dgram.createSocket("udp4");
    const datagrams = [];
    udp.on("message", (m) => datagrams.push(m));
    await new Promise((resolve) => udp.bind(0, "127.0.0.1", resolve));
    const closed = await collector(); // a port nothing listens on
    await new Promise((resolve) => closed.server.close(resolve));
    const HI2 = "tcp 10.20.0.5:11000";
    const HI3 = "tcp 10.20.0.5:11001";
    const UDP = "udp 10.20.0.5:11002";
    const DNS = "udp 10.0.0.53:53";
    const replay = await startBackend(deps);
    try {
      await replay.request("open", { path: path.join(FIXTURES, "replay.pcap") }, { timeoutMs: 0 });
      const { page, problems, post } = await newPage(browser);
      const log = [];
      /** What a Load Setup… answers (set by the test). */
      let setupToLoad = null;
      // A stand-in for ReplayPanel (src/panels/replayPanel.ts).
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        log.push(msg);
        const filter = (scope) => (scope === "filter" ? "tcp" : "");
        if (msg.type === "ready") {
          await post({
            type: "init",
            title: "Replay to Service · replay.pcap",
            filter: "tcp",
            destinations: { [HI2]: { ip: "127.0.0.1", port: hi2.port } },
            options: { speed: 0, loops: 1, scope: "all", order: "sequence", jitter: 0, loss: 0 },
            presets: [
              {
                name: "Local",
                targets: {
                  [HI2]: { ip: "127.0.0.1", port: hi2.port },
                  "tcp 10.20.0.9:11001": { ip: "127.0.0.1", port: hi3.port }, // same port
                  [UDP]: { ip: "127.0.0.1", port: udp.address().port },
                },
              },
            ],
            allowPublic: false,
            running: false,
          });
        } else if (msg.type === "targets") {
          const params = { filter: filter(msg.scope), capture: msg.capture, files: msg.files };
          replay.request("replay_targets", params, { timeoutMs: 0 }).then(
            (res) => post({ type: "targets", ...res }),
            (err) => post({ type: "error", where: "targets", message: err.message }),
          );
        } else if (msg.type === "start") {
          await post({ type: "started" });
          const onProgress = (p) => void post({ type: "progress", progress: p });
          const params = {
            filter: filter(msg.scope),
            capture: msg.capture,
            files: msg.files,
            order: msg.order,
            targets: msg.targets,
            speed: msg.speed,
            loops: msg.loops,
            jitter: msg.jitter,
            loss: msg.loss,
            allowPublic: false,
          };
          replay.request("replay", params, { timeoutMs: 0, onProgress }).then(
            (result) => post({ type: "done", result }),
            (err) =>
              post({
                type: "error",
                where: "replay",
                message: err.message,
                target: err.data?.target,
                publicTarget: /must be allowed explicitly/.test(err.message),
              }),
          );
        } else if (msg.type === "stop") {
          await replay.request("replay_stop", {});
        } else if (msg.type === "addCaptures") {
          await post({ type: "filesAdded", files: [later], enabled: true });
        } else if (msg.type === "loadSetup" && setupToLoad) {
          await post({ type: "setup", name: "replay-setup.json", ...setupToLoad });
        }
      });
      await page.setContent(renderPanelHtml(origin, "replay.js"), { waitUntil: "load" });
      pages.push(problems);
      await waitRows(page, 4);
      const all = await rows(page);
      assert.deepEqual(
        all.map((r) => [r[1], r[2], r[3], r[4]]),
        [
          [DNS, "DNS", "1", "1"],
          [HI2, "TCP", "3", "6"],
          [UDP, "UDP", "1", "3"],
          [HI3, "TCP", "2", "5"],
        ],
      );
      assert.match(all[3][10], /1 retransmitted \(sent once\), 1 gap/);
      const dest = (key) =>
        page.$eval(`tr[data-key="${key}"]`, (tr) =>
          [...tr.querySelectorAll("input[type=text]")].map((i) => i.value),
        );
      assert.deepEqual(await dest(HI2), ["127.0.0.1", String(hi2.port)], "remembered");
      assert.deepEqual(await dest(DNS), ["127.0.0.1", "53"], "the recorded port");
      assert.match(await page.textContent("#replay-status"), /^4 recorded targets, 0:00 of/);

      // The preset: the same key, or the same protocol and port; the others are unchecked.
      await page.selectOption("#replay-preset", "Local");
      assert.deepEqual(await dest(HI3), ["127.0.0.1", String(hi3.port)]);
      assert.equal(await page.isChecked(`tr[data-key="${DNS}"] input[type=checkbox]`), false);
      assert.match(await page.textContent("#replay-status"), /"Local": 3 of 4 recorded targets/);

      // A bad port blocks Start, with the reason.
      const port3 = `tr[data-key="${HI3}"] .replay-port`;
      await page.fill(port3, "70000");
      assert.ok(await page.isDisabled("#replay-start"));
      assert.equal(await page.getAttribute(port3, "aria-invalid"), "true");
      assert.match(await page.getAttribute("#replay-start", "title"), /port between 1 and 65535/);
      await page.fill(port3, String(hi3.port));
      assert.ok(!(await page.isDisabled("#replay-start")));

      await page.click("#replay-start");
      const start = await lastOfType(log, "start");
      assert.deepEqual(start, {
        type: "start",
        targets: {
          [HI2]: { ip: "127.0.0.1", port: hi2.port },
          [UDP]: { ip: "127.0.0.1", port: udp.address().port },
          [HI3]: { ip: "127.0.0.1", port: hi3.port },
        },
        speed: 0,
        loops: 1,
        scope: "all",
        order: "sequence",
        jitter: 0,
        loss: 0,
        capture: true,
        files: [],
      });
      await page.waitForFunction(() =>
        /^Done in/.test(document.querySelector("#replay-status")?.textContent ?? ""),
      );
      assert.match(await page.textContent("#replay-status"), /no errors\.$/);
      assert.equal(hi2.got.length, 3);
      assert.equal(hi3.got.length, 2);
      assert.equal(datagrams.length, 3);
      const result = (key) => page.textContent(`tr[data-key="${key}"] td:last-child`);
      assert.equal(await result(HI2), "3 of 3 opened");
      assert.equal(await result(UDP), "3 datagrams");
      assert.equal(await result(DNS), "Not replayed");
      const hi3Bytes = hi3.got.flat().reduce((n, b) => n + b.length, 0);
      assert.equal(
        await page.getAttribute(`tr[data-key="${HI3}"] td:nth-child(9)`, "title"),
        `${hi3Bytes.toLocaleString()} bytes`,
      );
      assert.ok(
        (await page.$$eval("#replay-log li", (lis) => lis.map((li) => li.textContent))).some((t) =>
          t.includes(`connection 1 to 127.0.0.1:${hi3.port} opened`),
        ),
      );

      // Nothing listening: the row says so, in the error color, and the log has why.
      await page.fill(port3, String(closed.port));
      await page.click("#replay-start");
      await page.waitForFunction(() =>
        /^Done in/.test(document.querySelector("#replay-status")?.textContent ?? ""),
      );
      assert.match(await page.textContent("#replay-status"), /2 errors \(see the log\)\.$/);
      assert.equal(await result(HI3), "0 of 2 opened, 2 refused");
      assert.ok(await page.$(`tr[data-key="${HI3}"] td.replay-failed`));
      assert.equal(await page.locator("#replay-log li.log-error").count(), 2);

      // A public destination is refused: the notice offers the setting.
      await page.fill(`tr[data-key="${HI3}"] .replay-ip`, "8.8.8.8");
      await page.click("#replay-start");
      await page.waitForSelector(".notice.error:not(.hidden)");
      assert.match(await page.textContent(".notice.error"), /must be allowed explicitly/);
      await page.click("button:has-text('Allow Public Destinations…')");
      await expectLast(log, { type: "openSetting" });

      // Real time, many loops: Stop ends it with a summary.
      await page.fill(`tr[data-key="${HI3}"] .replay-ip`, "127.0.0.1");
      await page.fill(port3, String(hi3.port));
      await page.selectOption("#replay-speed", "1");
      await page.fill("#replay-loops", "1000");
      await page.click("#replay-start");
      await page.waitForFunction(() =>
        /^Replaying/.test(document.querySelector("#replay-status")?.textContent ?? ""),
      );
      assert.ok(await page.isDisabled(port3), "no edits while replaying");
      await page.click("#replay-stop");
      await page.waitForFunction(() =>
        /^Stopped after .* \(\d+ of 1000 loops\)/.test(
          document.querySelector("#replay-status")?.textContent ?? "",
        ),
      );
      assert.ok(!(await page.isDisabled(port3)));

      // Another capture of the same delivery: its targets add up, it plays too.
      await page.selectOption("#replay-speed", "0");
      await page.fill("#replay-loops", "1");
      assert.ok(await page.isDisabled("#replay-order"), "one capture: no order to choose");
      assert.ok(await page.isDisabled("#replay-jitter"), "no pauses: no jitter");
      await page.click("#replay-add-captures");
      await page.waitForFunction(
        () =>
          document.querySelector(`table.replay tbody tr td:nth-child(4)`)?.textContent === "2" &&
          /4 targets/.test(document.querySelector(".replay-capture-list")?.textContent ?? ""),
      );
      const captureRows = () =>
        page.$$eval(".replay-capture-list tbody tr", (trs) =>
          trs.map((tr) => [tr.children[1].textContent, tr.children[2].textContent]),
        );
      assert.deepEqual(
        (await captureRows()).map((r) => r[0]),
        ["replay.pcap (open in the viewer)", "later.pcap"],
      );
      assert.match((await captureRows())[1][1], /^4 targets · 15 packets · 0:00$/);
      assert.equal((await rows(page)).find((r) => r[1] === HI2)?.[3], "6");
      await page.selectOption("#replay-order", "merged");
      assert.match(await page.textContent("#replay-status"), /\(merged\)\.$/);
      const before = hi2.got.length;
      await page.click("#replay-start");
      const both = await lastOfType(log, "start");
      assert.deepEqual([both.capture, both.files, both.order], [true, [later], "merged"]);
      await page.waitForFunction(() =>
        /^Done in .* \(2 captures\)/.test(
          document.querySelector("#replay-status")?.textContent ?? "",
        ),
      );
      assert.equal(hi2.got.length - before, 6);
      const lines = await page.$$eval("#replay-log li", (lis) => lis.map((li) => li.textContent));
      assert.ok(lines.some((t) => t.includes("Finished later.pcap: ")));

      // UDP loss and jitter are checked; until stopped needs no loop count.
      await page.fill("#replay-loss", "150");
      assert.match(await page.getAttribute("#replay-start", "title"), /UDP loss must be/);
      await page.fill("#replay-loss", "100");
      await page.check("#replay-forever");
      assert.ok(await page.isDisabled("#replay-loops"));
      await page.click("#replay-start");
      const forever = await lastOfType(log, "start");
      assert.deepEqual([forever.loops, forever.loss], [0, 100]);
      await page.waitForFunction(() =>
        /^Replaying/.test(document.querySelector("#replay-status")?.textContent ?? ""),
      );
      await page.click("#replay-stop");
      await page.waitForFunction(() =>
        /^Stopped after .* \(\d+ loops? of 2 captures\).*datagrams? lost on purpose/.test(
          document.querySelector("#replay-status")?.textContent ?? "",
        ),
      );
      assert.match(
        await page.textContent(`tr[data-key="${UDP}"] td:last-child`),
        /lost on purpose/,
      );

      // Save Setup… sends the panel as it is; Load Setup… applies one.
      await page.click(".replay-capture-list tbody tr:nth-child(2) input[type=checkbox]");
      await page.waitForFunction(
        () => document.querySelector(`table.replay tbody tr td:nth-child(4)`)?.textContent === "1",
      );
      await page.click("#replay-save-setup");
      const setup = (await lastOfType(log, "saveSetup")).setup;
      assert.deepEqual(setup.captures, [{ path: later, enabled: false }]);
      assert.equal(setup.includeOpen, true);
      assert.deepEqual(setup.targets[HI3], { ip: "127.0.0.1", port: hi3.port, enabled: true });
      assert.deepEqual(setup.options, {
        speed: 0, loops: 0, scope: "all", order: "merged", jitter: 0, loss: 100,
      }); // prettier-ignore
      setupToLoad = {
        setup: {
          ...setup,
          captures: [...setup.captures, { path: path.join(tmp, "gone.pcap"), enabled: true }],
          targets: { ...setup.targets, [HI3]: { ip: "127.0.0.2", port: 9, enabled: false } },
          options: { ...setup.options, loops: 2, loss: 0 },
        },
        problems: [],
        missing: [path.join(tmp, "gone.pcap")],
      };
      await page.click("#replay-load-setup");
      await page.waitForSelector(".notice.error:not(.hidden)");
      assert.match(await page.textContent(".notice.error"), /gone\.pcap wasn't found/);
      await page.waitForFunction(
        (key) => document.querySelector(`tr[data-key="${key}"] .replay-ip`)?.value === "127.0.0.2",
        HI3,
      );
      assert.equal(await page.isChecked(`tr[data-key="${HI3}"] input[type=checkbox]`), false);
      assert.equal(await page.inputValue("#replay-loops"), "2");
      assert.ok(!(await page.isChecked("#replay-forever")));
      assert.ok(await page.isDisabled(".replay-capture-list tbody tr:nth-child(3) input"));
      assert.match((await captureRows())[2][1], /^File not found$/);
      // (Back to the open capture alone, its destinations as before.)
      await page.click(`.replay-capture-list button[aria-label="Remove gone.pcap"]`);
      await page.click(`.replay-capture-list button[aria-label="Remove later.pcap"]`);
      await page.fill(`tr[data-key="${HI3}"] .replay-ip`, "127.0.0.1");
      await page.fill(port3, String(hi3.port));
      await page.check(`tr[data-key="${HI3}"] input[type=checkbox]`);
      await page.selectOption("#replay-preset", "Local"); // (a loaded setup cleared it)

      // Save Preset, the row menu, and the displayed packets only.
      await page.click("#replay-save-preset");
      const saved = await lastOfType(log, "savePreset");
      assert.equal(saved.name, "Local");
      assert.deepEqual(Object.keys(saved.targets).sort(), [HI2, HI3, UDP].sort());
      await page.click(`tr[data-key="${HI3}"] td:nth-child(2)`, { button: "right" });
      assert.deepEqual(await menuLabels(page), ["Go to Packet 20", "Copy"]);
      await pickMenu(page, "Go to Packet 20");
      await expectLast(log, { type: "goto", frame: 20 });
      await page.selectOption("#replay-scope", "filter");
      await waitRows(page, 2);
      assert.deepEqual(
        (await rows(page)).map((r) => r[1]),
        [HI2, HI3],
      );
    } finally {
      await replay.dispose();
      fs.rmSync(tmp, { recursive: true, force: true });
      hi2.server.close();
      hi3.server.close();
      udp.close();
    }
  });

  // PCAP_SCREENSHOTS=<folder>: every panel as its test left it, in a VS Code theme
  // (PCAP_SCREENSHOTS_THEME: dark, light or hc), for checking the styling.
  test("screenshots of every panel (only with PCAP_SCREENSHOTS)", async function () {
    if (!process.env.PCAP_SCREENSHOTS) {
      this.skip();
    }
    const { applyTheme } = require("../../scripts/themes");
    for (const [i, { page }] of pages.entries()) {
      await applyTheme(page, process.env.PCAP_SCREENSHOTS_THEME || "dark");
      const title = await page.evaluate(() => document.querySelector("h1, h2")?.textContent ?? "");
      const name = `${String(i).padStart(2, "0")}-${title.replace(/[^A-Za-z0-9]+/g, "-")}.png`;
      await page.screenshot({ path: path.join(process.env.PCAP_SCREENSHOTS, name) });
    }
  });

  test("accessibility: no WCAG A/AA violations in any panel (axe-core)", async () => {
    // Each panel as its test left it (tables filled, graphs drawn, a call selected…).
    const found = [];
    for (const { page } of pages) {
      const title = await page.evaluate(() => document.querySelector("h1, h2")?.textContent);
      for (const v of await axeViolations(page)) {
        found.push(`${title}: ${v}`);
      }
    }
    assert.deepEqual(found, []);
  });

  test("no script errors or CSP violations in any panel", () => {
    for (const p of pages) {
      assert.deepEqual(p.errors, []);
      assert.deepEqual(p.csp, []);
    }
  });
});
