// @ts-check
/**
 * Capture Overview panel: the capture at a glance, from the backend's
 * overview (one pass) plus capture_info and expert_summary. Cards: summary
 * tiles, packets (or bytes) over time, the busiest addresses, protocols, TCP
 * services, and HTTP, DNS and TLS. A card's row applies its filter in the
 * viewer (right-click for the other choices); each card opens the full
 * statistics it summarises.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  /** @type {any} */
  const kit = /** @type {any} */ (window).PcapPanel;
  const SVG = "http://www.w3.org/2000/svg";
  const CHART_WIDTH = 1000;
  const CHART_HEIGHT = 120;

  const state = {
    filter: "",
    limit: false,
    queryId: 0,
    busy: false,
    /** @type {"packets" | "bytes"} */ metric: "packets",
    /** @type {any} */ data: null,
    /** @type {any} */ info: null,
    /** @type {Record<string, number> | null} */ expert: null,
  };

  /** @param {string} tag @param {Record<string, string>} [attrs] @param {(Node | string)[]} [children] */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, v);
    }
    node.append(...children);
    return node;
  }

  /** @param {string} tag @param {Record<string, string | number>} [attrs] */
  function s(tag, attrs = {}) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    return node;
  }

  const count = (/** @type {number} */ n) => (n || 0).toLocaleString("en-US");

  const title = h("h1", { class: "panel-title" }, ["Capture Overview"]);
  const limitBox = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox" }));
  const limitLabel = h("label", {}, [limitBox, "Limit to display filter"]);
  const refresh = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "overview-refresh" }, ["Refresh"]),
    "refresh",
  );
  const toolbar = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Overview" }, [
    limitLabel,
    h("span", { class: "spacer" }),
    refresh,
  ]);
  const progress = h("div", {
    class: "replay-progress indeterminate hidden",
    role: "progressbar",
    "aria-label": "Counting",
    "aria-valuemin": "0",
    "aria-valuemax": "100",
  });
  const fill = h("div", { class: "progress-fill" });
  progress.append(fill);
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const status = h("div", { class: "status", role: "status" });
  const grid = h("div", { class: "overview-grid" });
  app().append(title, toolbar, progress, notice, status, grid);

  function app() {
    return /** @type {HTMLElement} */ (document.getElementById("app"));
  }

  limitBox.addEventListener("change", () => {
    state.limit = limitBox.checked;
    query();
  });
  refresh.addEventListener("click", () => query());

  function renderToolbar() {
    limitBox.checked = state.limit;
    limitBox.disabled = !state.filter;
    limitLabel.title = state.filter ? "" : "No display filter is applied in the capture";
    limitLabel.querySelector("code")?.remove();
    if (state.filter) {
      limitLabel.append(h("code", {}, [state.filter]));
    }
  }

  function query() {
    const id = ++state.queryId;
    state.busy = true;
    notice.classList.add("hidden");
    setProgress(null);
    status.textContent = "Counting…";
    vscode.postMessage({ type: "query", id, limit: state.limit && !!state.filter });
  }

  /** @param {number | null} fraction */
  function setProgress(fraction) {
    progress.classList.toggle("hidden", !state.busy);
    progress.classList.toggle("indeterminate", fraction === null);
    if (fraction === null) {
      progress.removeAttribute("aria-valuenow");
      fill.style.width = "";
    } else {
      const pct = Math.round(Math.max(0, Math.min(1, fraction)) * 100);
      progress.setAttribute("aria-valuenow", String(pct));
      fill.style.width = `${pct}%`;
    }
  }

  /** The filter the overview counted within ("" = every packet). */
  function scope() {
    return state.data?.filter || "";
  }

  /** @param {string} expr @param {boolean} [apply] */
  function applyFilter(expr, apply = true) {
    vscode.postMessage({ type: "filter", expr, apply });
  }

  /** @param {string} command */
  function openCommand(command) {
    vscode.postMessage({ type: "command", id: command });
  }

  /**
   * A card: a heading, an "Open …" link to the full statistics, and its body.
   * @param {string} name @param {Node[]} body @param {[string, string]} [open] [label, command]
   * @param {string} [extra] a class
   */
  function card(name, body, open, extra = "") {
    const id = `card-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    const head = h("div", { class: "overview-card-head" }, [h("h2", { id }, [name])]);
    if (open) {
      const link = h("button", { type: "button", class: "link", title: `Open ${open[0]}` }, [
        `Open ${open[0]}`,
      ]);
      link.addEventListener("click", () => openCommand(open[1]));
      head.append(link);
    }
    return h("section", { class: `overview-card ${extra}`.trim(), "aria-labelledby": id }, [
      head,
      ...body,
    ]);
  }

  /**
   * One breakdown as a list of rows (a button each: applies its filter).
   * @param {string} name
   * @param {{total: number, items: {label: string, count: number, bytes?: number, filter: string | null}[], more: number}} part
   * @param {{bytes?: boolean, of?: string}} [opts] `bytes`: sized and shown by bytes;
   *   `of`: what the share is of ("packets", "requests"…)
   */
  function breakdown(name, part, opts = {}) {
    const nodes = [];
    if (name) {
      nodes.push(h("h3", {}, [name]));
    }
    if (!part.items.length) {
      nodes.push(h("p", { class: "overview-note" }, ["None"]));
      return nodes;
    }
    const size = (/** @type {any} */ item) => (opts.bytes ? item.bytes || 0 : item.count);
    const max = opts.bytes
      ? Math.max(...part.items.map(size), 1)
      : Math.max(part.total || 0, ...part.items.map(size), 1);
    const list = h("ul", { class: "overview-list", "aria-label": name || "Rows" });
    for (const item of part.items) {
      const value = opts.bytes
        ? `${lib.formatBytes(item.bytes || 0)} · ${count(item.count)}`
        : count(item.count);
      const share = !opts.bytes && part.total ? Math.round((item.count / part.total) * 100) : null;
      const meter = h("span", { class: "overview-meter", "aria-hidden": "true" });
      const bar = h("span", { class: "overview-fill" });
      bar.style.width = `${Math.max(1, Math.round((size(item) / max) * 100))}%`;
      meter.append(bar);
      const describe = opts.bytes
        ? `${item.label}: ${lib.formatBytes(item.bytes || 0)} in ${count(item.count)} packets`
        : `${item.label}: ${count(item.count)}${share !== null ? ` (${share}% of ${opts.of || "packets"})` : ""}`;
      const row = h(
        "button",
        {
          type: "button",
          class: "overview-item",
          title: item.filter ? `${describe}\nApply as filter: ${item.filter}` : describe,
        },
        [
          h("span", { class: "overview-label" }, [item.label]),
          meter,
          h("span", { class: "overview-count" }, [value]),
        ],
      );
      if (item.filter) {
        row.dataset.filter = item.filter;
        row.addEventListener("click", () => applyFilter(withScope(item.filter || "")));
      } else {
        row.setAttribute("aria-disabled", "true");
      }
      row.dataset.label = item.label;
      list.append(h("li", {}, [row]));
    }
    nodes.push(list);
    if (part.more) {
      nodes.push(h("p", { class: "overview-note" }, [`and ${count(part.more)} more`]));
    }
    return nodes;
  }

  /** A row's filter, within the overview's own when it was limited. @param {string} expr */
  function withScope(expr) {
    const sc = scope();
    return sc ? `(${sc}) && (${expr})` : expr;
  }

  function summaryCard() {
    const o = state.data;
    const tiles = lib.overviewTiles(o, state.info);
    const list = h("dl", { class: "overview-tiles" });
    for (const t of tiles) {
      const tile = h("div", { class: "overview-tile" }, [
        h("dt", {}, [t.label]),
        h("dd", t.title ? { title: t.title } : {}, [t.value]),
      ]);
      list.append(tile);
    }
    const body = [list];
    if (state.expert) {
      const e = state.expert;
      const problems = h("p", { class: "overview-expert" });
      const parts = /** @type {[string, string, string][]} */ ([
        ["error", "error", "errors"],
        ["warning", "warning", "warnings"],
        ["note", "info", "notes"],
      ]);
      const button = h(
        "button",
        { type: "button", class: "link", title: "Open Expert Information" },
        [],
      );
      for (const [key, codicon, word] of parts) {
        const n = e[key] || 0;
        button.append(
          h("span", { class: `overview-severity ${key}` }, [
            kit.icon(codicon),
            ` ${count(n)} ${n === 1 ? word.slice(0, -1) : word}`,
          ]),
        );
      }
      button.addEventListener("click", () => openCommand("pcapViewer.statistics.expertInfo"));
      problems.append("Expert information: ", button);
      body.push(problems);
    }
    return card(
      "Summary",
      body,
      ["Capture Properties", "pcapViewer.statistics.captureProperties"],
      "wide",
    );
  }

  function timelineCard() {
    const t = state.data.timeline;
    const values = /** @type {number[]} */ (t[state.metric] || []);
    const max = Math.max(...values, 1);
    const metric = /** @type {HTMLSelectElement} */ (
      h("select", { "aria-label": "Count" }, [
        h("option", { value: "packets" }, ["Packets"]),
        h("option", { value: "bytes" }, ["Bytes"]),
      ])
    );
    metric.value = state.metric;
    metric.addEventListener("change", () => {
      state.metric = /** @type {"packets" | "bytes"} */ (metric.value);
      render();
      /** @type {HTMLElement | null} */ (grid.querySelector("select[aria-label='Count']"))?.focus();
    });
    const peak = lib.timelinePeak(t, state.metric);
    const unit = state.metric === "bytes" ? "bytes" : "packets";
    const show = (/** @type {number} */ v) =>
      state.metric === "bytes" ? lib.formatBytes(v) : count(v);
    const svg = s("svg", {
      class: "overview-timeline",
      viewBox: `0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`,
      preserveAspectRatio: "none",
      role: "img",
      "aria-label": peak
        ? `${unit} per ${lib.formatInterval(t.interval)}: busiest at ${lib.formatInterval(peak.start)} with ${show(peak.value)}`
        : `No ${unit}`,
    });
    const width = CHART_WIDTH / Math.max(values.length, 1);
    values.forEach((v, i) => {
      if (!v) {
        return;
      }
      const height = Math.max(1, (v / max) * (CHART_HEIGHT - 2));
      const rect = s("rect", {
        class: "overview-bar",
        x: i * width,
        y: CHART_HEIGHT - height,
        width: Math.max(width - (width > 4 ? 1 : 0), 0.5),
        height,
      });
      const tip = s("title");
      tip.textContent = `${lib.formatInterval(i * t.interval)}–${lib.formatInterval((i + 1) * t.interval)}: ${show(v)}`;
      rect.append(tip);
      rect.addEventListener("click", () => applyFilter(lib.timelineFilter(t.interval, i, scope())));
      svg.append(rect);
    });
    const axis = h("div", { class: "overview-axis" }, [
      h("span", {}, ["0 s"]),
      h("span", {}, [`${show(max)} max per ${lib.formatInterval(t.interval)}`]),
      h("span", {}, [lib.formatInterval(values.length * t.interval)]),
    ]);
    const body = [h("div", { class: "toolbar" }, [h("label", {}, ["Show ", metric])]), svg, axis];
    if (peak) {
      const busiest = h("button", { type: "button", class: "link", id: "overview-peak" }, [
        `Busiest: ${show(peak.value)} from ${lib.formatInterval(peak.start)}`,
      ]);
      busiest.title = `Apply as filter: ${lib.timelineFilter(t.interval, peak.index, scope())}`;
      busiest.addEventListener("click", () =>
        applyFilter(lib.timelineFilter(t.interval, peak.index, scope())),
      );
      body.push(h("p", {}, [busiest]));
    }
    return card("Packets over time", body, ["I/O Graph", "pcapViewer.statistics.ioGraph"], "wide");
  }

  function render() {
    const o = state.data;
    if (!o) {
      return;
    }
    const cards = [summaryCard(), timelineCard()];
    cards.push(
      card("Top addresses", breakdown("", o.addresses, { bytes: true }), [
        "Endpoints",
        "pcapViewer.statistics.endpoints",
      ]),
      card("Protocols", breakdown("", o.protocols, { of: "packets" }), [
        "Protocol Hierarchy",
        "pcapViewer.statistics.protocolHierarchy",
      ]),
      card("TCP services", breakdown("", o.services, { of: "connections" }), [
        "Conversations",
        "pcapViewer.statistics.conversations",
      ]),
    );
    const absent = [];
    if (o.http.requests || o.http.responses) {
      cards.push(
        card(
          "HTTP",
          [
            h("p", { class: "overview-note" }, [
              `${count(o.http.requests)} requests · ${count(o.http.responses)} responses`,
            ]),
            ...breakdown("Methods", o.http.methods, { of: "requests" }),
            ...breakdown("Status codes", o.http.statuses, { of: "responses" }),
            ...breakdown("Content types", o.http.contentTypes, { of: "responses" }),
            ...breakdown("Hosts", o.http.hosts, { of: "requests" }),
          ],
          ["HTTP Requests", "pcapViewer.statistics.httpRequests"],
        ),
      );
    } else {
      absent.push("HTTP");
    }
    if (o.dns.queries || o.dns.responses) {
      cards.push(
        card(
          "DNS",
          [
            h("p", { class: "overview-note" }, [
              `${count(o.dns.queries)} queries · ${count(o.dns.responses)} responses`,
            ]),
            ...breakdown("Results", o.dns.rcodes, { of: "responses" }),
            ...breakdown("Query types", o.dns.types, { of: "queries" }),
            ...breakdown("Names", o.dns.names, { of: "queries" }),
          ],
          ["DNS Queries", "pcapViewer.statistics.dnsQueries"],
        ),
      );
    } else {
      absent.push("DNS");
    }
    if (o.tls.clientHellos || o.tls.serverHellos) {
      cards.push(
        card(
          "TLS",
          [
            h("p", { class: "overview-note" }, [
              `${count(o.tls.clientHellos)} client hellos · ${count(o.tls.serverHellos)} server hellos`,
            ]),
            ...breakdown("Versions chosen", o.tls.versions, { of: "server hellos" }),
            ...breakdown("Server names", o.tls.servers, { of: "client hellos" }),
          ],
          ["TLS Servers", "pcapViewer.statistics.tlsServers"],
        ),
      );
    } else {
      absent.push("TLS");
    }
    grid.replaceChildren(...cards);
    const counted = scope() ? ` matching ${scope()}` : "";
    status.textContent =
      `${count(o.packets)} packets${counted}` +
      (absent.length ? ` · no ${absent.join(", ").replace(/, ([^,]*)$/, " or $1")}` : "");
  }

  kit.rowMenu(grid, {
    rows: ".overview-item",
    select: (/** @type {HTMLElement} */ row) => {
      for (const other of grid.querySelectorAll(".overview-item.selected")) {
        other.classList.remove("selected");
      }
      row.classList.add("selected");
      row.focus();
    },
    entries: (/** @type {HTMLElement} */ row) => {
      const expr = row.dataset.filter;
      const label = row.dataset.label || "";
      /** @type {any[]} */
      const entries = [];
      if (expr) {
        /** @param {boolean} apply */
        const choices = (apply) =>
          lib
            .filterChoices(state.filter, withScope(expr))
            .map((/** @type {{label: string, expr: string}} */ c) => ({
              label: c.label,
              hint: c.expr,
              title: c.expr,
              action: () => applyFilter(c.expr, apply),
            }));
        entries.push(
          { label: "Apply as Filter", icon: "filter", children: choices(true) },
          { label: "Prepare as Filter", icon: "edit", children: choices(false) },
        );
      }
      entries.push({
        label: "Copy",
        icon: "copy",
        children: [
          { label: "Name", action: () => vscode.postMessage({ type: "copy", text: label }) },
          ...(expr
            ? [{ label: "Filter", action: () => vscode.postMessage({ type: "copy", text: expr }) }]
            : []),
        ],
      });
      return entries;
    },
  });
  grid.addEventListener("focusin", (e) => {
    const row = /** @type {HTMLElement} */ (e.target).closest(".overview-item");
    if (row) {
      for (const other of grid.querySelectorAll(".overview-item.selected")) {
        other.classList.remove("selected");
      }
      row.classList.add("selected");
    }
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg.type) {
      case "init":
        state.filter = msg.filter || "";
        renderToolbar();
        query();
        return;
      case "filterChanged": {
        // (Limited to the capture's filter: count again with the new one, or all.)
        const recount = state.limit && (msg.filter || "") !== state.filter;
        state.filter = msg.filter || "";
        if (!state.filter) {
          state.limit = false;
        }
        renderToolbar();
        if (recount) {
          query();
        }
        return;
      }
      case "progress":
        if (msg.id === state.queryId) {
          if (typeof msg.message === "string") {
            status.textContent = msg.message;
          }
          setProgress(typeof msg.fraction === "number" ? msg.fraction : null);
        }
        return;
      case "result":
        if (msg.id !== state.queryId) {
          return;
        }
        state.busy = false;
        setProgress(null);
        state.data = msg.overview;
        state.info = msg.info || null;
        state.expert = msg.expert || null;
        render();
        return;
      case "error":
        if (msg.id !== state.queryId) {
          return;
        }
        state.busy = false;
        setProgress(null);
        status.textContent = "";
        notice.textContent = msg.cancelled ? "Cancelled." : msg.message;
        notice.classList.remove("hidden");
        return;
    }
  });

  vscode.postMessage({ type: "ready" });
})();
