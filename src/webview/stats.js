// @ts-check
/**
 * Statistics panel: renders a backend `stats` table (conversations, endpoints,
 * protocol hierarchy, IO graph, expert info, capture properties, HTTP, DNS,
 * packet lengths, service response time) with sorting (not of trees),
 * row actions (apply/prepare filter, go to packet), CSV copy and, for the IO
 * graph, a line chart. Untrusted text only goes through textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  const SVG = "http://www.w3.org/2000/svg";

  const TYPE_LABELS = { eth: "Ethernet", ip: "IPv4", ipv6: "IPv6", tcp: "TCP", udp: "UDP" };
  const HTTP_REPORTS = {
    packets: "Packet Counter",
    requests: "Requests",
    load: "Load Distribution",
  };
  // Mirrors stats.SRT_PROTOCOLS in the backend.
  const SRT_PROTOCOLS = {
    icmp: "ICMP",
    icmpv6: "ICMPv6",
    smb: "SMB",
    smb2: "SMB2",
    ldap: "LDAP",
    snmp: "SNMP",
    diameter: "Diameter",
    gtp: "GTP",
    gtpv2: "GTPv2",
    ncp: "NCP",
    afp: "AFP",
    camel: "CAMEL",
    fc: "Fibre Channel",
  };
  // Mirrors stats.IP_STATS_TYPES (IPv4 and IPv6 Statistics).
  const IP_REPORTS = {
    addresses: "All Addresses",
    srcdst: "Source and Destination Addresses",
    ptype: "Protocol Types",
    dests: "Destinations and Ports",
  };
  /** Reports that are trees: their row order is the tree's, so no sorting. */
  const TREES = ["phs", "http", "dns", "plen", "sip", "ipv4", "ipv6"];
  /** @type {Record<string, string>} */
  const DEFAULT_TYPE = { http: "packets", srt: "auto", ipv4: "addresses", ipv6: "addresses" };
  const INTERVALS = [
    ["", "Auto"],
    ["0.001", "1 ms"],
    ["0.01", "10 ms"],
    ["0.1", "100 ms"],
    ["1", "1 s"],
    ["10", "10 s"],
    ["60", "1 min"],
  ];

  const state = {
    kind: "",
    filter: "",
    type: "tcp",
    interval: "",
    limit: false,
    /** The IO graph's graphs (lib.ioSeries) and its Y axis. */
    series: [{ metric: "packets", filter: "", field: "", style: "line" }],
    logScale: false,
    /** The graph whose filter or field the last query refused. @type {number | null} */
    badSeries: null,
    /** @type {any} */ table: null,
    /** @type {{col: number, desc: boolean} | null} */ sort: null,
    /** @type {any} */ selected: null,
    queryId: 0,
    /** @type {number | null} */ pending: null,
    /** AI help is available (the host said so): offer "Ask Copilot…" on expert information. */
    ai: false,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  /**
   * @param {string} tag
   * @param {Record<string, string>} [attrs]
   * @param {(Node | string)[]} [children]
   */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") {
        node.className = v;
      } else {
        node.setAttribute(k, v);
      }
    }
    node.append(...children);
    return node;
  }

  /** A Codicons glyph (codicons/codicon.css), hidden from screen readers. @param {string} name */
  const icon = (name) => h("span", { class: `codicon codicon-${name}`, "aria-hidden": "true" });

  // ------------------------------------------------------------------ skeleton

  const title = h("h1", { class: "panel-title" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" });
  const actions = h("div", { class: "toolbar" });
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const seriesBox = h("div", { class: "io-series hidden", role: "group", "aria-label": "Graphs" });
  const chartBox = h("div", { class: "chart hidden", tabindex: "0", "aria-label": "I/O graph" });
  const legend = h("ul", { class: "io-legend hidden", "aria-label": "Legend" });
  const mapBox = h("div", { class: "geo-map hidden" });
  const tableBox = h("div");
  app.append(
    title,
    toolbar,
    seriesBox,
    actions,
    notice,
    status,
    chartBox,
    legend,
    mapBox,
    tableBox,
  );

  const applyBtn = h("button", { type: "button", title: "Apply this row as the display filter" }, [
    "Apply as Filter",
  ]);
  const prepareBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Put this row's filter in the filter bar" },
    ["Prepare as Filter"],
  );
  const gotoBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Select the first packet of this row" },
    ["Go to Packet"],
  );
  const copyBtn = h("button", { type: "button", class: "secondary" }, ["Copy as CSV"]);
  const askBtn = h(
    "button",
    {
      type: "button",
      class: "secondary",
      id: "ask-copilot",
      title:
        "Ask Copilot why the selected entry happens (no selection: the capture's errors and warnings). Sends expert information and conversation statistics, never packet contents.",
    },
    ["Ask Copilot…"],
  );
  askBtn.addEventListener("click", () => askCopilot());
  applyBtn.addEventListener("click", () => rowFilter(true));
  prepareBtn.addEventListener("click", () => rowFilter(false));
  gotoBtn.addEventListener("click", () => rowGoto());
  copyBtn.addEventListener("click", () => {
    if (state.table) {
      const shown = shownColumns();
      vscode.postMessage({
        type: "copy",
        text: lib.tableToCsv(
          shown.map((i) => state.table.columns[i]),
          sortedRows().map((/** @type {any} */ r) => ({ cells: shown.map((i) => r.cells[i]) })),
        ),
      });
    }
  });

  function buildToolbar() {
    toolbar.replaceChildren();
    if (state.kind === "conversations" || state.kind === "endpoints") {
      const select = h("select", { "aria-label": "Address type" });
      for (const [value, label] of Object.entries(TYPE_LABELS)) {
        const opt = h("option", { value }, [label]);
        if (value === state.type) {
          opt.setAttribute("selected", "");
        }
        select.append(opt);
      }
      select.addEventListener("change", () => {
        state.type = /** @type {HTMLSelectElement} */ (select).value;
        query();
      });
      toolbar.append(h("label", {}, ["Type ", select]));
    }
    if (["http", "srt", "ipv4", "ipv6"].includes(state.kind)) {
      toolbar.append(typeSelect());
    }
    if (state.kind === "io") {
      const interval = h("select", { "aria-label": "Interval" });
      for (const [value, label] of INTERVALS) {
        interval.append(h("option", { value }, [label]));
      }
      /** @type {HTMLSelectElement} */ (interval).value = state.interval;
      interval.addEventListener("change", () => {
        state.interval = /** @type {HTMLSelectElement} */ (interval).value;
        query();
      });
      const log = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox", id: "io-log" }));
      log.checked = state.logScale;
      log.addEventListener("change", () => {
        state.logScale = log.checked;
        rememberSeries();
        renderChart();
      });
      toolbar.append(h("label", {}, ["Interval ", interval]), h("label", {}, [log, "Log scale"]));
    }
    seriesBox.classList.toggle("hidden", state.kind !== "io");
    if (state.kind === "io") {
      renderSeriesEditor();
    }
    if (state.kind !== "properties") {
      const box = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox" }));
      box.checked = state.limit;
      box.disabled = !state.filter;
      box.addEventListener("change", () => {
        state.limit = box.checked;
        query();
      });
      const label = h(
        "label",
        { title: state.filter ? "" : "No display filter is applied in the capture" },
        [box, "Limit to display filter"],
      );
      if (state.filter) {
        label.append(" ", h("code", {}, [state.filter]));
      }
      toolbar.append(label);
    }
    const refresh = h("button", { type: "button", class: "secondary" }, ["Refresh"]);
    refresh.addEventListener("click", () => query());
    toolbar.append(h("span", { class: "spacer" }), refresh);
    actions.replaceChildren(
      ...(state.kind === "expert"
        ? [gotoBtn, applyBtn, prepareBtn, ...(state.ai ? [askBtn] : [])]
        : state.kind === "srt" || state.kind === "credentials"
          ? [applyBtn, prepareBtn, gotoBtn]
          : state.kind === "properties" || state.kind === "io"
            ? []
            : [applyBtn, prepareBtn]),
      copyBtn,
    );
    updateActions();
  }

  /** The HTTP report or SRT protocol picker; protocols with traffic are marked. */
  function typeSelect() {
    // HTTP and the IP statistics choose a report; service response time a protocol.
    const report = state.kind !== "srt";
    const select = /** @type {HTMLSelectElement} */ (
      h("select", { id: "stats-type", "aria-label": report ? "Report" : "Protocol" })
    );
    /** @type {Record<string, string>} */
    const choices =
      state.kind === "http" ? HTTP_REPORTS : state.kind === "srt" ? SRT_PROTOCOLS : IP_REPORTS;
    const available = (state.table && state.table.available) || [];
    for (const [value, label] of Object.entries(choices)) {
      const withTraffic = !report && available.includes(value);
      select.append(h("option", { value }, [withTraffic ? `${label} ●` : label]));
    }
    select.value = state.type in choices ? state.type : Object.keys(choices)[0];
    select.title = report
      ? ""
      : "● marks protocols this capture has traffic for (DCE-RPC, ONC-RPC and SCSI need arguments and aren't offered)";
    select.addEventListener("change", () => {
      state.type = select.value;
      query();
    });
    return h("label", {}, [report ? "Report " : "Protocol ", select]);
  }

  // ------------------------------------------------------------------ data

  function query() {
    if (state.pending !== null) {
      vscode.postMessage({ type: "cancel", id: state.pending });
    }
    const id = ++state.queryId;
    state.pending = id;
    status.textContent = "Running tshark…";
    notice.classList.add("hidden");
    vscode.postMessage({
      type: "query",
      id,
      params: {
        type: state.type,
        interval: state.interval ? Number(state.interval) : undefined,
        limit: state.limit,
        series:
          state.kind === "io"
            ? state.series.map(({ metric, filter, field }) => ({ metric, filter, field }))
            : undefined,
      },
    });
  }

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    if (msg.type === "init") {
      state.kind = msg.kind;
      state.type = DEFAULT_TYPE[msg.kind] || state.type;
      state.filter = msg.filter || "";
      state.ai = !!msg.ai;
      if (msg.io) {
        // The graphs last drawn (any capture), as the host kept them.
        const series = lib.ioSeries(msg.io.series, MAX_SERIES);
        state.series = series.length ? series : state.series;
        state.logScale = !!msg.io.logScale;
      }
      title.textContent = msg.title;
      buildToolbar();
      query();
    } else if (msg.type === "result" && msg.id === state.pending) {
      state.pending = null;
      state.table = msg.table;
      markBadSeries(null);
      state.selected = null;
      state.sort = null;
      title.textContent = msg.table.title;
      if (state.kind === "srt") {
        // "auto" came back as the protocol it picked, with the ones that have traffic.
        state.type = msg.table.type || state.type;
        buildToolbar();
      }
      render();
    } else if (msg.type === "error" && msg.id === state.pending) {
      state.pending = null;
      status.textContent = "";
      if (!msg.cancelled) {
        notice.textContent =
          typeof msg.series === "number" ? `Graph ${msg.series + 1}: ${msg.message}` : msg.message;
        notice.classList.remove("hidden");
        markBadSeries(typeof msg.series === "number" ? msg.series : null);
      }
    }
  });

  function sortedRows() {
    const rows = state.table ? state.table.rows : [];
    // Trees keep their order.
    if (!state.sort || TREES.includes(state.kind)) {
      return rows;
    }
    return lib.sortRows(rows, state.sort.col, state.sort.desc);
  }

  // ------------------------------------------------------------------ table

  function render() {
    const t = state.table;
    const n = t.rows.length;
    const scope = t.filter ? ` matching ${t.filter}` : "";
    status.textContent =
      t.kind === "io"
        ? `${n} intervals of ${lib.formatCell(t.interval)} s${scope}`
        : t.kind === "properties"
          ? ""
          : t.unfiltered
            ? `${n.toLocaleString()} ${n === 1 ? "row" : "rows"} (this report covers the whole capture: it can't be limited to the display filter)`
            : `${n.toLocaleString()} ${n === 1 ? "row" : "rows"}${scope}`;
    chartBox.classList.toggle("hidden", t.kind !== "io");
    legend.classList.toggle("hidden", t.kind !== "io");
    if (t.kind === "io") {
      renderChart();
    }
    renderMap();
    renderTable();
    updateActions();
  }

  /**
   * GeoIP endpoints on a world map (worldmap.js's land outline): one point
   * per place, sized by bytes, its addresses as the tooltip; a click selects
   * the place's first row. The table stays the accessible view.
   */
  function renderMap() {
    const t = state.table;
    const world = /** @type {any} */ (window).PcapWorldMap;
    const cols = t.columns.map((/** @type {any} */ c) => c.id);
    const points =
      t.geoip && world
        ? lib.geoPoints(t.rows, cols.indexOf("bytes"), (/** @type {any} */ row) =>
            [row.cells[0], row.cells[cols.indexOf("city")], row.cells[cols.indexOf("country")]]
              .filter((v) => v)
              .join(", "),
          )
        : [];
    mapBox.classList.toggle("hidden", !points.length);
    if (!points.length) {
      mapBox.replaceChildren();
      return;
    }
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${world.width} ${world.height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute(
      "aria-label",
      `Map of ${points.length} ${points.length === 1 ? "place" : "places"} with endpoints`,
    );
    const land = document.createElementNS(SVG, "path");
    land.setAttribute("d", world.land);
    land.setAttribute("class", "land");
    svg.append(land);
    for (const point of points) {
      const dot = document.createElementNS(SVG, "circle");
      dot.setAttribute("cx", String(point.x));
      dot.setAttribute("cy", String(point.y));
      dot.setAttribute("r", String(point.r));
      dot.setAttribute("class", "geo-point");
      if (point.rows.includes(state.selected)) {
        dot.classList.add("selected");
      }
      const tip = document.createElementNS(SVG, "title");
      tip.textContent = point.label;
      dot.append(tip);
      dot.addEventListener("click", () => {
        state.selected = point.rows[0];
        renderMap();
        renderTable();
        updateActions();
        tableBox.querySelector("tr.selected")?.scrollIntoView({ block: "nearest" });
      });
      svg.append(dot);
    }
    mapBox.replaceChildren(svg);
  }

  /**
   * The columns the table shows (indexes into the cells): all, except that an IO
   * graph with graphs shows the times and the graphs (its every-packet columns
   * would repeat graph 1).
   */
  function shownColumns() {
    const t = state.table;
    const all = t.columns.map((/** @type {any} */ _c, /** @type {number} */ i) => i);
    return t.kind === "io" && t.series
      ? all.filter((/** @type {number} */ i) => !["packets", "bytes"].includes(t.columns[i].id))
      : all;
  }

  function renderTable() {
    const t = state.table;
    const shown = shownColumns();
    const headRow = h("tr");
    shown.forEach((/** @type {number} */ i) => {
      const col = t.columns[i];
      const sorted = state.sort && state.sort.col === i;
      const th = h("th", { class: col.numeric ? "num" : "", scope: "col" }, [
        col.label,
        ...(sorted ? [icon(state.sort.desc ? "triangle-down" : "triangle-up")] : []),
      ]);
      if (!TREES.includes(state.kind) && state.kind !== "properties") {
        th.setAttribute(
          "aria-sort",
          state.sort && state.sort.col === i
            ? state.sort.desc
              ? "descending"
              : "ascending"
            : "none",
        );
        th.addEventListener("click", () => {
          state.sort =
            !state.sort || state.sort.col !== i
              ? { col: i, desc: col.numeric }
              : { col: i, desc: !state.sort.desc };
          renderTable();
        });
      }
      headRow.append(th);
    });
    const body = h("tbody");
    for (const row of sortedRows()) {
      const tr = h("tr");
      shown.forEach((/** @type {number} */ i) => {
        const value = row.cells[i];
        const col = t.columns[i];
        const td = h("td", { class: col.numeric ? "num" : "" });
        if (i === 0 && row.depth) {
          td.style.paddingLeft = `${8 + row.depth * 16}px`;
        }
        if (t.kind === "expert" && col.id === "severity") {
          td.append(h("span", { class: `sev sev-${String(value)}` }, [String(value)]));
        } else {
          td.textContent = lib.formatCell(value);
        }
        if (t.kind === "expert" && col.id === "summary") {
          td.classList.add("wrap");
        }
        tr.append(td);
      });
      if (row === state.selected) {
        tr.classList.add("selected");
      }
      tr.addEventListener("click", () => {
        state.selected = row;
        [...body.children].forEach((r) => r.classList.toggle("selected", r === tr));
        if (row.geo) {
          renderMap();
        }
        updateActions();
      });
      tr.addEventListener("dblclick", () => (row.frame ? rowGoto() : rowFilter(true)));
      body.append(tr);
    }
    tableBox.replaceChildren(h("table", { class: "stats" }, [h("thead", {}, [headRow]), body]));
  }

  function updateActions() {
    const row = state.selected;
    applyBtn.toggleAttribute("disabled", !row || !row.filter);
    prepareBtn.toggleAttribute("disabled", !row || !row.filter);
    gotoBtn.toggleAttribute("disabled", !row || !row.frame);
    copyBtn.toggleAttribute("disabled", !state.table);
    if (state.kind === "expert" && row && !row.filter) {
      // Expert rows filter on the message text.
      applyBtn.toggleAttribute("disabled", false);
      prepareBtn.toggleAttribute("disabled", false);
    }
  }

  /** @param {boolean} apply */
  function rowFilter(apply) {
    const row = state.selected;
    if (!row) {
      return;
    }
    const expr =
      row.filter ||
      (state.kind === "expert"
        ? `_ws.expert.message == ${lib.quoteFilterString(String(row.cells[1]))}`
        : "");
    if (expr) {
      vscode.postMessage({ type: "filter", expr, apply });
    }
  }

  /** The expert row as the host's anomaly explanation takes it. */
  function expertRow(/** @type {any} */ row) {
    const cols = state.table.columns;
    const cell = (/** @type {string} */ id) =>
      row.cells[cols.findIndex((/** @type {any} */ c) => c.id === id)];
    return {
      severity: String(cell("severity") ?? ""),
      group: String(cell("group") ?? ""),
      protocol: String(cell("protocol") ?? ""),
      summary: String(cell("summary") ?? ""),
      count: Number(cell("count")) || 1,
      frames: (row.frames || (row.frame ? [row.frame] : [])).slice(0, 20),
    };
  }

  function askCopilot() {
    if (state.kind !== "expert" || !state.table) {
      return;
    }
    const rows = state.selected ? [expertRow(state.selected)] : [];
    vscode.postMessage({ type: "askCopilot", rows });
  }

  function rowGoto() {
    if (state.selected && state.selected.frame) {
      vscode.postMessage({ type: "goto", frame: state.selected.frame });
    }
  }

  // ------------------------------------------------------------------ IO graphs

  const MAX_SERIES = 8;
  const METRICS = [
    ["packets", "Packets"],
    ["bytes", "Bytes"],
    ["bits", "Bits"],
    ["sum", "SUM(field)"],
    ["count", "COUNT(field)"],
    ["max", "MAX(field)"],
    ["min", "MIN(field)"],
    ["avg", "AVG(field)"],
    ["load", "LOAD(field)"],
  ];
  const FIELD_METRICS = ["sum", "count", "max", "min", "avg", "load"];
  const UNITS = { packets: "packets", bytes: "bytes", bits: "bits" };

  /** The graphs are kept by the host, so the next I/O graph starts with them. */
  function rememberSeries() {
    vscode.postMessage({ type: "ioGraphs", series: state.series, logScale: state.logScale });
  }

  /** @param {number | null} index */
  function markBadSeries(index) {
    state.badSeries = index;
    seriesBox.querySelectorAll(".io-graph").forEach((row, i) => {
      for (const input of row.querySelectorAll("input[type='text']")) {
        input.toggleAttribute("aria-invalid", i === index);
        input.classList.toggle("invalid", i === index);
      }
    });
  }

  /** One row per graph: filter, Y axis, field (field metrics), style, remove; then Add. */
  function renderSeriesEditor() {
    seriesBox.replaceChildren();
    state.series.forEach((graph, i) => {
      const n = i + 1;
      const filter = /** @type {HTMLInputElement} */ (
        h("input", {
          type: "text",
          class: "io-filter",
          "aria-label": `Display filter of graph ${n}`,
          placeholder: "All packets (or a display filter)",
          spellcheck: "false",
        })
      );
      filter.value = graph.filter;
      const metric = /** @type {HTMLSelectElement} */ (
        h("select", { class: "io-metric", "aria-label": `Y axis of graph ${n}` })
      );
      for (const [value, label] of METRICS) {
        metric.append(h("option", { value }, [label]));
      }
      metric.value = graph.metric;
      const field = /** @type {HTMLInputElement} */ (
        h("input", {
          type: "text",
          class: "io-field",
          "aria-label": `Field of graph ${n}`,
          placeholder: "Field, e.g. tcp.analysis.ack_rtt",
          spellcheck: "false",
        })
      );
      field.value = graph.field;
      field.classList.toggle("hidden", !FIELD_METRICS.includes(graph.metric));
      const style = /** @type {HTMLSelectElement} */ (
        h("select", { class: "io-style", "aria-label": `Style of graph ${n}` })
      );
      style.append(
        h("option", { value: "line" }, ["Line"]),
        h("option", { value: "bar" }, ["Bar"]),
      );
      style.value = graph.style;
      const remove = h(
        "button",
        {
          type: "button",
          class: "icon io-remove",
          "aria-label": `Remove graph ${n}`,
          title: "Remove this graph",
        },
        [icon("trash")],
      );
      remove.toggleAttribute("disabled", state.series.length === 1);
      /** A change that needs tshark again. */
      const changed = () => {
        graph.filter = filter.value.trim();
        graph.metric = metric.value;
        graph.field = field.value.trim();
        field.classList.toggle("hidden", !FIELD_METRICS.includes(graph.metric));
        rememberSeries();
        if (FIELD_METRICS.includes(graph.metric) && !graph.field) {
          field.focus(); // (asked for when it has one)
          return;
        }
        query();
      };
      filter.addEventListener("change", changed);
      field.addEventListener("change", changed);
      metric.addEventListener("change", changed);
      for (const input of [filter, field]) {
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            input.blur(); // (fires change when edited)
          }
        });
      }
      style.addEventListener("change", () => {
        graph.style = style.value === "bar" ? "bar" : "line";
        rememberSeries();
        renderChart();
      });
      remove.addEventListener("click", () => {
        state.series.splice(i, 1);
        rememberSeries();
        renderSeriesEditor();
        query();
      });
      seriesBox.append(
        h("div", { class: "io-graph" }, [
          h("span", { class: `io-swatch s${i}`, "aria-hidden": "true" }),
          h("span", { class: "io-name" }, [`Graph ${n}`]),
          filter,
          metric,
          field,
          style,
          remove,
        ]),
      );
    });
    const add = h("button", { type: "button", class: "secondary io-add" }, [
      icon("add"),
      " Add Graph",
    ]);
    add.toggleAttribute("disabled", state.series.length >= MAX_SERIES);
    add.addEventListener("click", () => {
      state.series.push({ metric: "packets", filter: "", field: "", style: "line" });
      rememberSeries();
      renderSeriesEditor();
      /** @type {HTMLInputElement | null} */ (
        seriesBox.querySelector(".io-graph:last-of-type .io-filter")
      )?.focus();
      query();
    });
    seriesBox.append(add);
    markBadSeries(state.badSeries);
  }

  const CHART_HEIGHT = 220;
  const MARGIN = { top: 12, right: 16, bottom: 28, left: 64 };
  let hoverIndex = -1;
  /** Chart width at the last render: only a width change needs a redraw. */
  let renderedWidth = -1;

  /** @param {string} tag @param {Record<string, string | number>} attrs */
  function s(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    return node;
  }

  /**
   * The graphs the table holds: each series' column and how it is drawn (the
   * table came back for `table.series`, which may predate an edit of the styles).
   */
  function chartSeries() {
    const t = state.table;
    const cols = t.columns.map((/** @type {any} */ c) => c.id);
    const drawn = t.series || [{ metric: "packets", filter: "", field: "", label: "Packets" }];
    return drawn.map((/** @type {any} */ g, /** @type {number} */ i) => {
      const at = cols.indexOf(`s${i}`);
      return {
        index: i,
        label: String(g.label),
        unit: /** @type {Record<string, string>} */ (UNITS)[g.metric] || "",
        style: state.series[i] ? state.series[i].style : "line",
        values: t.rows.map((/** @type {any} */ r) => Number(r.cells[at >= 0 ? at : 2]) || 0),
      };
    });
  }

  function renderChart() {
    const t = state.table;
    if (!t || t.kind !== "io") {
      return;
    }
    const graphs = chartSeries();
    const width = Math.max(320, chartBox.clientWidth || 600);
    renderedWidth = chartBox.clientWidth;
    const innerW = width - MARGIN.left - MARGIN.right;
    const innerH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
    const rows = t.rows;
    const xMax = rows.length ? rows[rows.length - 1].cells[1] : 1;
    const all = graphs.flatMap((g) => g.values);
    const positive = all.filter((v) => v > 0);
    const log = state.logScale && positive.length > 0;
    const ticks = log
      ? lib.logTicks(Math.min(...positive), Math.max(...positive))
      : lib.niceTicks(Math.max(0, ...all));
    const yMin = log ? ticks[0] : 0;
    const yMax = ticks[ticks.length - 1] || 1;
    const x = (/** @type {number} */ v) => MARGIN.left + (v / (xMax || 1)) * innerW;
    const bottom = MARGIN.top + innerH;
    const y = (/** @type {number} */ v) =>
      log
        ? v <= 0
          ? bottom
          : bottom -
            ((Math.log10(v) - Math.log10(yMin)) / (Math.log10(yMax) - Math.log10(yMin))) * innerH
        : bottom - (v / yMax) * innerH;
    // Each interval is plotted at its midpoint.
    const mids = rows.map((/** @type {any} */ r) => x((r.cells[0] + r.cells[1]) / 2));

    const names = graphs.map((g) => g.label).join(", ");
    const svg = s("svg", {
      viewBox: `0 0 ${width} ${CHART_HEIGHT}`,
      height: CHART_HEIGHT,
      role: "img",
      "aria-label": `${names} per ${lib.formatCell(t.interval)} s interval${log ? " (log scale)" : ""}`,
    });
    const grid = s("g", { class: "grid" });
    const axis = s("g", { class: "axis" });
    for (const tick of ticks) {
      const ty = Math.round(y(tick)) + 0.5;
      grid.append(s("line", { x1: MARGIN.left, x2: width - MARGIN.right, y1: ty, y2: ty }));
      const label = s("text", { x: MARGIN.left - 8, y: ty + 4, "text-anchor": "end" });
      label.textContent = lib.formatCell(tick);
      axis.append(label);
    }
    for (const tick of lib.niceTicks(xMax, 6)) {
      if (tick > xMax) {
        break;
      }
      const label = s("text", { x: x(tick), y: CHART_HEIGHT - 8, "text-anchor": "middle" });
      label.textContent = `${lib.formatCell(tick)} s`;
      axis.append(label);
    }
    svg.append(grid, axis);
    // Bars first (lines stay visible over them), side by side within an interval.
    const bars = graphs.filter((g) => g.style === "bar");
    bars.forEach((g, k) => {
      const group = s("g", { class: `series-bars s${g.index}` });
      rows.forEach((/** @type {any} */ r, /** @type {number} */ i) => {
        const x0 = x(r.cells[0]);
        const span = Math.max(1, x(r.cells[1]) - x0);
        const w = (span * 0.8) / bars.length;
        const top = y(g.values[i]);
        if (bottom - top > 0) {
          group.append(
            s("rect", {
              x: (x0 + span * 0.1 + k * w).toFixed(1),
              y: top.toFixed(1),
              width: Math.max(1, w - 0.5).toFixed(1),
              height: (bottom - top).toFixed(1),
            }),
          );
        }
      });
      svg.append(group);
    });
    for (const g of graphs.filter((g) => g.style === "line")) {
      if (!rows.length) {
        break;
      }
      const line = g.values
        .map((v, i) => `${i ? "L" : "M"}${mids[i].toFixed(1)},${y(v).toFixed(1)}`)
        .join("");
      if (graphs.length === 1) {
        svg.append(
          s("path", {
            class: `series-area s${g.index}`,
            d: `${line}L${mids[mids.length - 1].toFixed(1)},${bottom.toFixed(1)}L${mids[0].toFixed(1)},${bottom.toFixed(1)}Z`,
          }),
        );
      }
      svg.append(s("path", { class: `series-line s${g.index}`, d: line }));
    }
    const crosshair = s("line", { class: "crosshair hidden", y1: MARGIN.top, y2: bottom });
    const markers = graphs.map((g) => s("circle", { class: `marker hidden s${g.index}`, r: 4 }));
    // Hit area larger than the marks: the whole plot.
    const overlay = s("rect", {
      x: MARGIN.left,
      y: MARGIN.top,
      width: innerW,
      height: innerH,
      fill: "transparent",
    });
    svg.append(crosshair, ...markers, overlay);
    const tooltip = h("div", { class: "tooltip hidden", role: "status" });
    chartBox.replaceChildren(svg, tooltip);
    legend.replaceChildren(
      ...graphs.map((g) =>
        h("li", {}, [
          h("span", { class: `io-swatch s${g.index}`, "aria-hidden": "true" }),
          g.label,
        ]),
      ),
    );

    const show = (/** @type {number} */ i) => {
      hoverIndex = i;
      const row = rows[i];
      if (!row) {
        return;
      }
      const px = mids[i];
      crosshair.setAttribute("x1", String(px));
      crosshair.setAttribute("x2", String(px));
      crosshair.classList.remove("hidden");
      graphs.forEach((g, k) => {
        markers[k].setAttribute("cx", String(px));
        markers[k].setAttribute("cy", String(y(g.values[i])));
        markers[k].classList.remove("hidden");
      });
      const [start, end] = row.cells;
      const value = (/** @type {(typeof graphs)[number]} */ g) =>
        `${lib.formatCell(g.values[i])}${g.unit ? ` ${g.unit}` : ""}`;
      tooltip.replaceChildren(
        // One graph: its value large, as before; several: one line each.
        ...(graphs.length === 1
          ? [h("strong", {}, [value(graphs[0])])]
          : graphs.map((g) =>
              h("div", { class: "tooltip-row" }, [
                h("span", { class: `io-swatch s${g.index}`, "aria-hidden": "true" }),
                `${g.label}: `,
                h("strong", {}, [value(g)]),
              ]),
            )),
        h("span", { class: "tooltip-time" }, [`${lib.formatCell(start)}–${lib.formatCell(end)} s`]),
      );
      tooltip.classList.remove("hidden");
      const box = chartBox.getBoundingClientRect();
      const scale = box.width / width;
      const top = Math.min(...graphs.map((g) => y(g.values[i])));
      tooltip.style.left = `${Math.min(px * scale + 12, box.width - tooltip.offsetWidth - 4)}px`;
      tooltip.style.top = `${Math.max(0, top * scale - 40)}px`;
    };
    const hide = () => {
      hoverIndex = -1;
      crosshair.classList.add("hidden");
      markers.forEach((m) => m.classList.add("hidden"));
      tooltip.classList.add("hidden");
    };
    overlay.addEventListener("pointermove", (e) => {
      const box = svg.getBoundingClientRect();
      const px = ((e.clientX - box.left) / box.width) * width;
      let best = 0;
      mids.forEach((m, i) => {
        if (Math.abs(m - px) < Math.abs(mids[best] - px)) {
          best = i;
        }
      });
      show(best);
    });
    overlay.addEventListener("pointerleave", hide);
    chartBox.onkeydown = (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const next = hoverIndex < 0 ? 0 : hoverIndex + (e.key === "ArrowRight" ? 1 : -1);
        show(Math.max(0, Math.min(rows.length - 1, next)));
      } else if (e.key === "Home" || e.key === "End") {
        e.preventDefault();
        show(e.key === "Home" ? 0 : rows.length - 1);
      } else if (e.key === "Escape") {
        hide();
      }
    };
    chartBox.onblur = hide;
    // A redraw (resize, style switch) keeps the hovered point: the old overlay is
    // gone without a pointerleave, and the pointer may not move again.
    if (hoverIndex >= 0) {
      show(Math.min(hoverIndex, rows.length - 1));
    }
  }

  new ResizeObserver(() => {
    if (state.table && state.table.kind === "io" && chartBox.clientWidth !== renderedWidth) {
      renderChart();
    }
  }).observe(chartBox);

  vscode.postMessage({ type: "ready" });
})();
