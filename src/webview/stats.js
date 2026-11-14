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
  /** The least room (characters) the widest text column of a long table keeps. */
  const FLEX_MIN_CH = 24;

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
  const TREES = ["phs", "http", "dns", "plen", "sip", "ipv4", "ipv6", "sequences"];
  /** The sequence check's counter wraps (sequenceModel.SEQUENCE_WRAPS). */
  const WRAPS = [
    [0, "Doesn't wrap"],
    [2 ** 8, "8 bits (256)"],
    [2 ** 16, "16 bits (65,536)"],
    [2 ** 24, "24 bits"],
    [2 ** 32, "32 bits"],
  ];
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
    /** The sequence check's fields, wrap and restart window. */
    sequence: { key: /** @type {string[]} */ ([]), seq: "", wrap: 0, reorder: 1000 },
    /** The field the last sequence check refused. @type {string | null} */
    badField: null,
    /** The table's text filter (lib.searchRows): rows already loaded, no query. */
    search: "",
    /** The query the table shown answers (its activity charts come after it). @type {number | null} */
    resultId: null,
    /** TCP/UDP conversations grouped by their two hosts (lib.groupConversations). */
    grouped: false,
    /** The groups shown open (their keys). @type {Set<string>} */
    expanded: new Set(),
  };

  /** The grouped rows of the table shown (kept, so a selected row stays the same object). */
  let groupedCache = {
    table: /** @type {any} */ (null),
    type: "",
    rows: /** @type {any[]} */ ([]),
  };

  /** Conversations of TCP or UDP, grouped by hosts. */
  function grouping() {
    return (
      state.grouped &&
      state.kind === "conversations" &&
      (state.type === "tcp" || state.type === "udp") &&
      !!state.table
    );
  }

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  const h = /** @type {any} */ (window).PcapPanel.h;

  const kit = /** @type {any} */ (window).PcapPanel;
  /** A Codicons glyph (codicons/codicon.css), hidden from screen readers. @param {string} name */
  const icon = (/** @type {string} */ name) => kit.icon(name);
  /** A button with a Codicon before its label. */
  const iconButton = (
    /** @type {string} */ name,
    /** @type {string} */ label,
    /** @type {Record<string, string>} */ attrs = {},
  ) => kit.withIcon(h("button", { type: "button", ...attrs }, [label]), name);

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
  const searchInput = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "stats-search",
      type: "search",
      placeholder: "Filter rows",
      "aria-label": "Filter rows (every word, in any column)",
      spellcheck: "false",
    })
  );
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let searchTimer;
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => setSearch(searchInput.value), 150);
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && searchInput.value) {
      e.preventDefault();
      e.stopPropagation();
      searchInput.value = "";
      clearTimeout(searchTimer);
      setSearch("");
    } else if (e.key === "Enter") {
      clearTimeout(searchTimer);
      setSearch(searchInput.value);
    }
  });
  // Ctrl/Cmd+F: the table's filter (the webview's own find is not offered).
  document.addEventListener("keydown", (e) => {
    if (
      (e.ctrlKey || e.metaKey) &&
      !e.altKey &&
      e.key.toLowerCase() === "f" &&
      searchInput.isConnected
    ) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  /** Applies the text filter: redraws the table, drops a selection it hides. @param {string} text */
  function setSearch(text) {
    if (text === state.search) {
      return;
    }
    state.search = text;
    if (!state.table) {
      return;
    }
    if (state.selected && !shownRows().includes(state.selected)) {
      state.selected = null;
    }
    render();
  }
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

  const applyBtn = iconButton("filter", "Apply as Filter", {
    title: "Apply this row as the display filter",
  });
  const prepareBtn = iconButton("edit", "Prepare as Filter", {
    class: "secondary",
    title: "Put this row's filter in the filter bar",
  });
  const gotoBtn = iconButton("go-to-file", "Go to Packet", {
    class: "secondary",
    title: "Select the first packet of this row",
  });
  const copyBtn = iconButton("copy", "Copy as CSV", { class: "secondary" });
  const askBtn = iconButton("sparkle", "Ask Copilot…", {
    class: "secondary",
    id: "ask-copilot",
    title:
      "Ask Copilot why the selected entry happens (no selection: the capture's errors and warnings). Sends expert information and conversation statistics, never packet contents.",
  });
  const bodyBtn = iconButton("file-media", "Show Response Body", {
    class: "secondary",
    id: "show-body",
    title: "Show the response's body (text, image or hex) in Show Packet Bytes",
  });
  bodyBtn.addEventListener("click", () => state.selected && showBody(state.selected));
  const exchangeBtn = iconButton("arrow-swap", "Show Request and Response", {
    class: "secondary",
    id: "show-exchange",
    title: "Show the request and its response: headers and bodies, pretty-printed",
  });
  exchangeBtn.addEventListener("click", () => state.selected && showExchange(state.selected));
  askBtn.addEventListener("click", () => askCopilot());
  applyBtn.addEventListener("click", () => rowFilter(true));
  prepareBtn.addEventListener("click", () => rowFilter(false));
  gotoBtn.addEventListener("click", () => rowGoto());
  copyBtn.addEventListener("click", () => copyTable());

  function copyTable() {
    if (state.table) {
      const shown = shownColumns();
      vscode.postMessage({
        type: "copy",
        text: lib.tableToCsv(
          shown.map((i) => state.table.columns[i]),
          shownRows().map((/** @type {any} */ r) => ({ cells: shown.map((i) => r.cells[i]) })),
        ),
      });
    }
  }

  /** @param {string} text */
  const copy = (text) => vscode.postMessage({ type: "copy", text });

  /** The table rows' objects, by their <tr> (the row menu's). @type {WeakMap<Element, any>} */
  const rowOf = new WeakMap();

  // A row's menu: right-click, or Shift+F10 / the menu key for the selected row.
  kit.rowMenu(tableBox, {
    rows: "table.stats tbody tr:not(.spacer)",
    select: (/** @type {HTMLElement} */ tr) => {
      if (!tr.classList.contains("selected")) {
        tr.click();
      }
    },
    entries: (/** @type {HTMLElement} */ tr, /** @type {HTMLElement | null} */ cell) =>
      rowEntries(rowOf.get(tr), cell),
  });

  /**
   * The row menu: the row's filter (Apply/Prepare as Filter ›, combined with
   * the capture's filter like the viewer's), its packet, Ask Copilot for an
   * expert entry, and copies.
   * @param {any} row @param {HTMLElement | null} cell
   */
  function rowEntries(row, cell) {
    if (!row) {
      return null;
    }
    /** @type {any[]} */
    const entries = [];
    const expr = rowExpr(row);
    if (expr) {
      /** @param {boolean} apply */
      const choices = (apply) =>
        lib
          .filterChoices(state.filter, expr)
          .map((/** @type {{label: string, expr: string}} */ c) => ({
            label: c.label,
            hint: c.expr,
            title: c.expr,
            action: () => vscode.postMessage({ type: "filter", expr: c.expr, apply }),
          }));
      entries.push(
        { label: "Apply as Filter", icon: "filter", children: choices(true) },
        { label: "Prepare as Filter", icon: "edit", children: choices(false) },
      );
    }
    if (row.frame) {
      entries.push({ label: `Go to Packet ${row.frame}`, icon: "go-to-file", action: rowGoto });
    }
    if (state.kind === "expert" && state.ai) {
      entries.push({ label: "Ask Copilot About This Entry…", icon: "sparkle", action: askCopilot });
    }
    if (state.kind === "http_requests") {
      entries.push({
        label: "Show Request and Response",
        icon: "arrow-swap",
        action: () => showExchange(row),
      });
      if (row.response) {
        entries.push({
          label: "Show Response Body",
          icon: "file-media",
          action: () => showBody(row),
        });
      }
      entries.push({
        label: "Show Request in New Window",
        icon: "window",
        action: () => vscode.postMessage({ type: "packetWindow", frame: row.frame }),
      });
      if (row.response) {
        entries.push({
          label: "Show Response in New Window",
          icon: "window",
          action: () => vscode.postMessage({ type: "packetWindow", frame: row.response }),
        });
      }
    }
    const shown = shownColumns();
    /** @type {any[]} */
    const copies = [];
    const value = cell ? (cell.textContent ?? "") : "";
    if (value) {
      copies.push({ label: "Value", hint: value, action: () => copy(value) });
    }
    copies.push({
      label: "Row",
      action: () => copy(shown.map((i) => lib.formatCell(row.cells[i])).join("\t")),
    });
    if (expr) {
      copies.push({ label: "As Filter", hint: expr, action: () => copy(expr) });
    }
    copies.push({ label: "Table as CSV", action: () => copyTable() });
    if (entries.length) {
      entries.push("-");
    }
    entries.push({ label: "Copy", icon: "copy", children: copies });
    return entries;
  }

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
        buildToolbar();
        query();
      });
      toolbar.append(h("label", {}, ["Type ", select]));
      if (state.kind === "conversations" && (state.type === "tcp" || state.type === "udp")) {
        const box = /** @type {HTMLInputElement} */ (
          h("input", { type: "checkbox", id: "stats-group" })
        );
        box.checked = state.grouped;
        box.addEventListener("change", () => {
          state.grouped = box.checked;
          state.selected = null;
          if (state.table) {
            render();
          }
        });
        toolbar.append(
          h("label", { title: "One row per pair of hosts, its connections under it" }, [
            box,
            "Group by hosts",
          ]),
        );
      }
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
    if (state.kind === "sequences") {
      toolbar.append(...sequenceInputs());
    }
    seriesBox.classList.toggle("hidden", state.kind !== "io");
    if (state.kind === "io") {
      renderSeriesEditor();
    }
    if (state.kind !== "properties") {
      const box = /** @type {HTMLInputElement} */ (
        h("input", { type: "checkbox", id: "stats-limit" })
      );
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
    if (state.kind !== "properties" && state.kind !== "io") {
      searchInput.value = state.search;
      toolbar.append(searchInput);
    }
    const refresh = iconButton("refresh", "Refresh", { class: "secondary" });
    refresh.addEventListener("click", () => query());
    toolbar.append(h("span", { class: "spacer" }), refresh);
    actions.replaceChildren(
      ...(state.kind === "expert"
        ? [gotoBtn, applyBtn, prepareBtn, ...(state.ai ? [askBtn] : [])]
        : state.kind === "http_requests"
          ? [applyBtn, prepareBtn, gotoBtn, exchangeBtn, bodyBtn]
          : state.kind === "srt" ||
              state.kind === "credentials" ||
              state.kind === "sequences" ||
              lib.SESSION_KINDS.includes(state.kind)
            ? [applyBtn, prepareBtn, gotoBtn]
            : state.kind === "properties" || state.kind === "io"
              ? []
              : [applyBtn, prepareBtn]),
      copyBtn,
    );
    updateActions();
  }

  /**
   * The sequence check's inputs: the fields naming a stream (comma-separated),
   * the field numbering its messages, the counter's wrap and the drop that
   * counts as a restart; Check (or Enter) runs it.
   */
  function sequenceInputs() {
    const text = (/** @type {string} */ id, /** @type {string} */ value, placeholder = "") => {
      const input = /** @type {HTMLInputElement} */ (
        h("input", { type: "text", id, spellcheck: "false", placeholder })
      );
      input.value = value;
      return input;
    };
    const key = text("seq-key", state.sequence.key.join(", "), "e.g. gtp.teid");
    const seq = text("seq-field", state.sequence.seq, "e.g. gtp.seq_number");
    const wrap = /** @type {HTMLSelectElement} */ (h("select", { id: "seq-wrap" }));
    for (const [value, label] of WRAPS) {
      wrap.append(h("option", { value: String(value) }, [String(label)]));
    }
    wrap.value = String(state.sequence.wrap);
    const reorder = /** @type {HTMLInputElement} */ (
      h("input", { type: "number", id: "seq-reorder", min: "1", step: "1" })
    );
    reorder.value = String(state.sequence.reorder);
    for (const [input, field] of [
      [key, state.sequence.key],
      [seq, [state.sequence.seq]],
    ]) {
      if (state.badField && /** @type {string[]} */ (field).includes(state.badField)) {
        /** @type {HTMLElement} */ (input).setAttribute("aria-invalid", "true");
      }
    }
    const run = iconButton("play", "Check", { id: "seq-run" });
    const start = () => {
      state.sequence = {
        key: key.value
          .split(",")
          .map((k) => k.trim())
          .filter((k) => k),
        seq: seq.value.trim(),
        wrap: Number(wrap.value),
        reorder: Math.max(1, Math.round(Number(reorder.value)) || 1000),
      };
      if (!state.sequence.seq) {
        seq.focus();
        status.textContent = "Name the field that numbers the messages.";
        return;
      }
      query();
    };
    run.addEventListener("click", start);
    for (const input of [key, seq, reorder]) {
      input.addEventListener("keydown", (/** @type {KeyboardEvent} */ e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          start();
        }
      });
    }
    return [
      h("label", { title: "The fields whose values name a stream, separated by commas" }, [
        "Streams by ",
        key,
      ]),
      h("label", { title: "The field that numbers each stream's messages" }, [
        "Sequence field ",
        seq,
      ]),
      h("label", { title: "Where the counter starts again at 0" }, ["Counter wraps at ", wrap]),
      h(
        "label",
        {
          title:
            "A number this much lower than the highest seen is a restart of the numbering, not a late message",
        },
        ["Restart after a drop of more than ", reorder],
      ),
      run,
    ];
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
        sequence: state.kind === "sequences" ? state.sequence : undefined,
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
      if (msg.sequence) {
        state.sequence = msg.sequence;
      }
      title.textContent = msg.title;
      buildToolbar();
      if (state.kind !== "sequences" || state.sequence.seq) {
        query();
      } else {
        status.textContent =
          "Name the field that numbers the messages, and the fields that name a stream, then Check.";
        document.getElementById("seq-key")?.focus();
      }
    } else if (msg.type === "sequence") {
      // A new sequence check in this panel (a command with fields).
      state.sequence = msg.sequence;
      state.badField = null;
      buildToolbar();
      query();
    } else if (msg.type === "result" && msg.id === state.pending) {
      state.pending = null;
      state.table = msg.table;
      markBadSeries(null);
      if (state.badField) {
        state.badField = null;
        buildToolbar();
      }
      state.selected = null;
      state.sort = null;
      title.textContent = msg.table.title;
      if (state.kind === "srt") {
        // "auto" came back as the protocol it picked, with the ones that have traffic.
        state.type = msg.table.type || state.type;
        buildToolbar();
      }
      state.resultId = msg.id;
      render();
    } else if (msg.type === "activity" && msg.id === state.resultId && state.table) {
      // Conversations' and endpoints' activity over time, after their rows
      // (the same table, row for row).
      if (msg.activity && Array.isArray(msg.rows) && msg.rows.length === state.table.rows.length) {
        state.table.activity = msg.activity;
        groupedCache.table = null;
        state.table.rows.forEach((/** @type {any} */ row, /** @type {number} */ i) => {
          if (Array.isArray(msg.rows[i])) {
            row.activity = msg.rows[i];
          }
        });
        renderTable();
      }
    } else if (msg.type === "error" && msg.id === state.pending) {
      state.pending = null;
      status.textContent = "";
      if (!msg.cancelled) {
        notice.textContent =
          typeof msg.series === "number" ? `Graph ${msg.series + 1}: ${msg.message}` : msg.message;
        notice.classList.remove("hidden");
        markBadSeries(typeof msg.series === "number" ? msg.series : null);
        if (state.kind === "sequences") {
          state.badField = typeof msg.field === "string" ? msg.field : null;
          buildToolbar();
        }
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

  /**
   * The rows drawn: sorted, grouped by hosts when asked (a closed group's
   * connections left out), then the text filter's (which opens the groups
   * it matches in).
   */
  function shownRows() {
    if (!grouping()) {
      const rows = sortedRows();
      return searchable() ? lib.searchRows(rows, state.search) : rows;
    }
    if (groupedCache.table !== state.table || groupedCache.type !== state.type) {
      groupedCache = {
        table: state.table,
        type: state.type,
        rows: lib.groupConversations(state.table, state.type),
      };
    }
    const rows = state.sort
      ? lib.sortGrouped(groupedCache.rows, state.sort.col, state.sort.desc)
      : groupedCache.rows;
    if (searchable()) {
      return lib.searchRows(rows, state.search);
    }
    return rows.filter(
      (/** @type {any} */ r) => r.parent === undefined || state.expanded.has(r.parent),
    );
  }

  /** The text filter applies (not to the I/O graph's intervals or the properties). */
  function searchable() {
    return !!state.search.trim() && state.kind !== "io" && state.kind !== "properties";
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
            : t.kind === "sequences"
              ? `${lib.sequenceSummary(t.summary)}${scope}`
              : t.summary
                ? `${lib.sessionSummary(t.kind, t.summary)}${scope}${
                    t.more
                      ? ` · the first ${n.toLocaleString()} listed (${t.more.toLocaleString()} more: limit to a display filter to see them)`
                      : ""
                  }`
                : `${n.toLocaleString()} ${n === 1 ? "row" : "rows"}${scope}`;
    if (grouping()) {
      const pairs = new Set(
        t.rows.map((/** @type {any} */ r) =>
          [lib.endAddress(String(r.cells[0])), lib.endAddress(String(r.cells[1]))].sort().join(" "),
        ),
      ).size;
      status.textContent += ` · ${pairs.toLocaleString()} ${pairs === 1 ? "pair" : "pairs"} of hosts`;
    }
    if (searchable()) {
      const shown = shownRows().length;
      status.textContent += ` · ${shown.toLocaleString()} shown (filter “${state.search.trim()}”)`;
    }
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
        revealSelected();
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
    // A group's button keeps the focus when the table is drawn again (opening
    // it, the activity charts arriving).
    const focusedGroup = document.activeElement
      ? toggleGroup.get(document.activeElement)
      : undefined;
    try {
      drawTable();
    } finally {
      if (focusedGroup !== undefined) {
        for (const b of tableBox.querySelectorAll("button.group-toggle")) {
          if (toggleGroup.get(b) === focusedGroup) {
            /** @type {HTMLElement} */ (b).focus();
          }
        }
      }
    }
  }

  function drawTable() {
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
    // Conversations and endpoints: each row's activity over time (activity.py).
    const activity = t.activity && (t.kind === "conversations" || t.kind === "endpoints");
    if (activity) {
      headRow.append(
        h("th", { scope: "col", class: "spark", title: activityTitle(t.activity) }, ["Activity"]),
      );
    }
    const body = h("tbody");
    const rows = shownRows();
    const virtual = rows.length > lib.VIRTUAL_TABLE_ROWS;
    /** One <tr> for row `index` of `rows`. @param {any} row @param {number} index */
    const rowElement = (row, index) => {
      const tr = h("tr");
      if (virtual) {
        tr.setAttribute("aria-rowindex", String(index + 2)); // (the header is row 1)
      }
      shown.forEach((/** @type {number} */ i) => {
        const value = row.cells[i];
        const col = t.columns[i];
        const td = h("td", { class: col.numeric ? "num" : "" });
        if (i === 0 && row.depth) {
          td.style.paddingLeft = `${8 + row.depth * 16}px`;
        }
        if (i === 0 && row.group !== undefined) {
          td.append(groupToggle(row));
        }
        if (t.kind === "expert" && col.id === "severity") {
          td.append(h("span", { class: `sev sev-${String(value)}` }, [String(value)]));
        } else {
          td.append(lib.formatCell(value));
        }
        if (t.kind === "expert" && col.id === "summary") {
          td.classList.add("wrap");
        }
        tr.append(td);
      });
      if (activity) {
        tr.append(sparkCell(row.activity, t.activity.interval));
      }
      rowOf.set(tr, row);
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
      return tr;
    };
    const table = h("table", { class: virtual ? "stats virtual" : "stats" });
    if (virtual) {
      // Fixed column widths (the cells are monospaced), so the columns don't
      // move as other rows are drawn; the screen reader hears every row.
      const chars = lib.columnChars(
        shown.map((/** @type {number} */ i) => t.columns[i].label),
        rows,
        shown,
      );
      // The widest text column takes the room left over (no width of its own).
      let flexible = -1;
      shown.forEach((/** @type {number} */ i, /** @type {number} */ j) => {
        if (!t.columns[i].numeric && (flexible < 0 || chars[j] > chars[flexible])) {
          flexible = j;
        }
      });
      const cols = h("colgroup");
      chars.forEach((width, j) => {
        const col = h("col");
        if (j !== flexible) {
          col.style.width = `calc(${width}ch + ${2 * 8}px)`;
        }
        cols.append(col);
      });
      if (activity) {
        const col = h("col");
        col.style.width = `${SPARK_WIDTH + 2 * 8}px`;
        cols.append(col);
      }
      table.append(cols);
      // Never narrower than every column needs, the flexible one at least
      // FLEX_MIN_CH: when the sized columns fill the panel, the table
      // scrolls sideways instead of squeezing that column to nothing.
      const need = chars.reduce(
        (sum, width, j) => sum + (j === flexible ? Math.min(width, FLEX_MIN_CH) : width),
        0,
      );
      table.style.minWidth = `calc(${need}ch + ${chars.length * 2 * 8}px${
        activity ? ` + ${SPARK_WIDTH + 2 * 8}px` : ""
      })`;
      table.setAttribute("aria-rowcount", String(rows.length + 1));
      headRow.setAttribute("aria-rowindex", "1");
    }
    table.append(h("thead", {}, [headRow]), body);
    tableBox.replaceChildren(table);
    if (!virtual) {
      virtualTable = null;
      rows.forEach((row, index) => body.append(rowElement(row, index)));
      if (!rows.length && searchable()) {
        const td = h("td", { colspan: String(shown.length), class: "empty" }, [
          `No row holds “${state.search.trim()}”.`,
        ]);
        body.append(h("tr", { class: "no-match" }, [td]));
      }
      return;
    }
    virtualTable = {
      rows,
      body,
      rowElement,
      columns: shown.length + (activity ? 1 : 0),
      rowHeight: 0,
      start: -1,
      end: -1,
    };
    drawWindow();
  }

  /**
   * A host pair's open/close button: a chevron and its number of
   * connections (searching opens every group it matches in).
   * @param {any} row
   */
  function groupToggle(row) {
    const open = searchable() || state.expanded.has(row.group);
    const button = h(
      "button",
      {
        type: "button",
        class: "icon group-toggle",
        "aria-expanded": String(open),
        "aria-label": `${open ? "Hide" : "Show"} the ${row.count} ${
          row.count === 1 ? "connection" : "connections"
        } between these hosts`,
        title: `${row.count} ${row.count === 1 ? "connection" : "connections"}`,
      },
      [icon(open ? "chevron-down" : "chevron-right"), String(row.count)],
    );
    button.addEventListener("click", (e) => {
      e.stopPropagation();
      if (state.expanded.has(row.group)) {
        state.expanded.delete(row.group);
      } else {
        state.expanded.add(row.group);
      }
      button.focus(); // (renderTable keeps the focus on this group's new button)
      renderTable();
    });
    toggleGroup.set(button, row.group);
    return button;
  }

  /** Each group toggle's group key. @type {WeakMap<Element, string>} */
  const toggleGroup = new WeakMap();

  /** The activity chart's size (px). */
  const SPARK_WIDTH = 96;
  const SPARK_HEIGHT = 16;

  /** The Activity column's tooltip: what a chart covers. @param {{interval: number, buckets: number}} a */
  function activityTitle(a) {
    return `Bytes over time: the capture in ${a.buckets} intervals of ${lib.formatInterval(a.interval)}, each row on its own scale`;
  }

  /**
   * A row's activity chart (bars, its busiest interval in words as its
   * name); an empty cell for a row without one.
   * @param {number[] | undefined} values @param {number} interval
   */
  function sparkCell(values, interval) {
    const td = h("td", { class: "spark" });
    if (!values) {
      return td;
    }
    const svg = s("svg", {
      width: SPARK_WIDTH,
      height: SPARK_HEIGHT,
      viewBox: `0 0 ${SPARK_WIDTH} ${SPARK_HEIGHT}`,
      role: "img",
      "aria-label": lib.activityLabel(values, interval),
    });
    for (const bar of lib.activityBars(values, SPARK_WIDTH, SPARK_HEIGHT)) {
      svg.append(s("rect", { x: bar.x, y: bar.y, width: bar.w, height: bar.h }));
    }
    svg.append(s("title", {}, lib.activityLabel(values, interval)));
    td.append(svg);
    return td;
  }

  /**
   * The table drawn a window at a time (more than lib.VIRTUAL_TABLE_ROWS
   * rows: drawing all of a 300k-row DNS table never finished): its sorted
   * rows, its <tbody>, a row's element, the measured row height and the
   * window drawn. @type {any}
   */
  let virtualTable = null;

  /** A spacer row standing for `count` rows not drawn. @param {number} count */
  function spacer(count) {
    const td = h("td", { colspan: String(virtualTable.columns) });
    td.style.height = `${count * virtualTable.rowHeight}px`;
    return h("tr", { class: "spacer", "aria-hidden": "true" }, [td]);
  }

  /** Draws the rows on screen (and a margin) of a long table; again on scroll. */
  function drawWindow() {
    const v = virtualTable;
    if (!v || !v.body.isConnected) {
      return;
    }
    if (!v.rowHeight) {
      // One row tells every row's height (cells don't wrap in a long table).
      const probe = v.rowElement(v.rows[0], 0);
      v.body.replaceChildren(probe);
      v.rowHeight = probe.getBoundingClientRect().height || 20;
    }
    const offset = -v.body.getBoundingClientRect().top;
    const { start, end } = lib.tableWindow(offset, window.innerHeight, v.rowHeight, v.rows.length);
    if (start === v.start && end === v.end) {
      return;
    }
    v.start = start;
    v.end = end;
    const parts = [];
    if (start > 0) {
      parts.push(spacer(start));
    }
    for (let i = start; i < end; i++) {
      parts.push(v.rowElement(v.rows[i], i));
    }
    if (end < v.rows.length) {
      parts.push(spacer(v.rows.length - end));
    }
    v.body.replaceChildren(...parts);
  }

  /** Scrolls a long table's selected row into view (it may not be drawn). */
  function revealSelected() {
    const v = virtualTable;
    const index = v ? v.rows.indexOf(state.selected) : -1;
    if (index < 0) {
      tableBox.querySelector("tr.selected")?.scrollIntoView({ block: "nearest" });
      return;
    }
    const top = v.body.getBoundingClientRect().top + window.scrollY + index * v.rowHeight;
    window.scrollTo({ top: Math.max(0, top - window.innerHeight / 2) });
    drawWindow();
  }

  for (const event of ["scroll", "resize"]) {
    window.addEventListener(event, () => requestAnimationFrame(drawWindow), { passive: true });
  }

  function updateActions() {
    const row = state.selected;
    applyBtn.toggleAttribute("disabled", !row || !row.filter);
    prepareBtn.toggleAttribute("disabled", !row || !row.filter);
    gotoBtn.toggleAttribute("disabled", !row || !row.frame);
    bodyBtn.toggleAttribute("disabled", !row || !row.response);
    exchangeBtn.toggleAttribute("disabled", !row || !row.frame);
    copyBtn.toggleAttribute("disabled", !state.table);
    if (state.kind === "expert" && row && !row.filter) {
      // Expert rows filter on the message text.
      applyBtn.toggleAttribute("disabled", false);
      prepareBtn.toggleAttribute("disabled", false);
    }
  }

  /** A row's filter: its own, or an expert entry's message. @param {any} row */
  function rowExpr(row) {
    return (
      row.filter ||
      (state.kind === "expert"
        ? `_ws.expert.message == ${lib.quoteFilterString(String(row.cells[1]))}`
        : "")
    );
  }

  /** @param {boolean} apply */
  function rowFilter(apply) {
    const row = state.selected;
    const expr = row ? rowExpr(row) : "";
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

  /** An HTTP row's response body, in Show Packet Bytes. @param {any} row */
  /** An HTTP Requests row's request and response, in the HTTP Exchange panel. @param {any} row */
  function showExchange(row) {
    if (row && row.frame) {
      vscode.postMessage({
        type: "httpExchange",
        request: row.frame,
        requestIndex: row.requestIndex ?? 0,
        response: row.response ?? null,
        responseIndex: row.responseIndex ?? 0,
        label: row.label,
      });
    }
  }

  function showBody(row) {
    if (row && row.response) {
      vscode.postMessage({ type: "httpBody", frame: row.response, label: row.label });
    }
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

  const s = /** @type {any} */ (window).PcapPanel.s;

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
