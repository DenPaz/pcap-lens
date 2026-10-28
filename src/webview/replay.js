// @ts-check
/**
 * Replay to Service panel: the capture's recorded targets (the server ends of
 * its TCP connections and UDP flows), an IP and port for each, presets, speed
 * and loops; then the replay's live counts per target, a log and a summary.
 * The backend reads the capture and owns the sockets (replay.py). Addresses
 * and protocol names come from the capture, so they only go through
 * textContent and input values.
 */
(function () {
  "use strict";

  const kit = /** @type {any} */ (window).PcapPanel;
  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;

  /** Log lines kept on the page (the oldest go first). */
  const MAX_LOG_LINES = 2000;
  const SPEEDS = [
    { value: 1, label: "Real time (1×)" },
    { value: 2, label: "2×" },
    { value: 5, label: "5×" },
    { value: 10, label: "10×" },
    { value: 100, label: "100×" },
    { value: 0, label: "No pauses" },
  ];

  /**
   * @typedef {{key: string, proto: string, ip: string, port: number, connections: number,
   *   packets: number, bytes: number, retransmissions: number, gaps: number,
   *   firstFrame: number, protocol: string}} Target
   * @typedef {{ip: string, port: number}} Destination
   * @typedef {{name: string, targets: Record<string, Destination>}} Preset
   * @typedef {{key: string, connections: number, opened: number, refused: number, reset: number,
   *   bytes: number, dropped: number, received: number, datagrams: number, errorCount: number}} Stats
   * @typedef {{tr: HTMLTableRowElement, use: HTMLInputElement, ip: HTMLInputElement,
   *   port: HTMLInputElement, sent: HTMLElement, received: HTMLElement, result: HTMLElement}} Row
   */
  const state = {
    /** @type {Target[] | null} */ targets: null,
    filter: "",
    /** @type {Preset[]} */ presets: [],
    allowPublic: false,
    /** @type {Record<string, Destination>} */ remembered: {},
    /** @type {Map<string, Row>} */ rows: new Map(),
    /** @type {string | null} */ selected: null,
    running: false,
    loading: false,
    /** The loops of the running (or last) replay. */
    loops: 1,
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

  // ------------------------------------------------------------------ skeleton

  const title = h("h1", { class: "panel-title" }, ["Replay to Service"]);
  const intro = h("p", { class: "status replay-intro" }, [
    "Each recorded connection is opened again to its destination and carries what the client sent, with the recorded pauses; the service's answers are counted.",
  ]);
  const scopeSelect = /** @type {HTMLSelectElement} */ (
    h("select", { id: "replay-scope", "aria-label": "Packets to replay" }, [
      h("option", { value: "all" }, ["All packets"]),
      h("option", { value: "filter" }, ["Displayed packets"]),
    ])
  );
  const presetSelect = /** @type {HTMLSelectElement} */ (
    h("select", { id: "replay-preset", "aria-label": "Preset" })
  );
  const savePresetBtn = kit.withIcon(
    h("button", { type: "button", id: "replay-save-preset", class: "secondary" }, ["Save Preset…"]),
    "save",
  );
  const deletePresetBtn = h(
    "button",
    {
      type: "button",
      id: "replay-delete-preset",
      class: "icon",
      title: "Delete the preset",
      "aria-label": "Delete the preset",
    },
    [kit.icon("trash")],
  );
  const refreshBtn = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "replay-refresh" }, ["Refresh"]),
    "refresh",
  );
  const toolbar = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Targets" }, [
    h("label", {}, ["Packets ", scopeSelect]),
    h("label", {}, ["Preset ", presetSelect]),
    savePresetBtn,
    deletePresetBtn,
    h("span", { class: "spacer" }),
    refreshBtn,
  ]);
  const allIp = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "replay-all-ip",
      type: "text",
      value: "127.0.0.1",
      spellcheck: "false",
      "aria-label": "IP address for every target",
    })
  );
  const allIpBtn = h("button", { type: "button", id: "replay-all-ip-apply", class: "secondary" }, [
    "Same IP for All",
  ]);
  const speedSelect = /** @type {HTMLSelectElement} */ (
    h("select", { id: "replay-speed", "aria-label": "Speed" })
  );
  const loopsInput = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "replay-loops",
      type: "number",
      min: "1",
      max: "1000",
      value: "1",
      "aria-label": "Loops",
    })
  );
  const startBtn = kit.withIcon(
    h("button", { type: "button", id: "replay-start" }, ["Start Replay"]),
    "debug-start",
  );
  const stopBtn = kit.withIcon(
    h("button", { type: "button", id: "replay-stop", class: "secondary" }, ["Stop"]),
    "debug-stop",
  );
  const options = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Replay" }, [
    h("label", {}, ["IP ", allIp]),
    allIpBtn,
    h("label", {}, ["Speed ", speedSelect]),
    h("label", {}, ["Loops ", loopsInput]),
    h("span", { class: "spacer" }),
    startBtn,
    stopBtn,
  ]);
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const noticeText = h("span");
  const allowBtn = h("button", { type: "button", class: "link hidden" }, [
    "Allow Public Destinations…",
  ]);
  notice.append(noticeText, " ", allowBtn);
  const statusText = h("span", { id: "replay-status" });
  const status = h("div", { class: "status", role: "status" }, [statusText]);
  const fill = h("div", { class: "progress-fill" });
  const bar = h(
    "div",
    {
      class: "replay-progress hidden",
      role: "progressbar",
      "aria-label": "Replay progress",
      "aria-valuemin": "0",
      "aria-valuemax": "100",
    },
    [fill],
  );
  const tableBox = h("div", { class: "replay-targets" });
  const logHead = h("h2", { class: "panel-subtitle-h" }, ["Log"]);
  const log = h("ol", { id: "replay-log", class: "replay-log", "aria-label": "Replay log" });
  app.append(title, intro, toolbar, tableBox, options, notice, status, bar, logHead, log);

  for (const s of SPEEDS) {
    speedSelect.append(h("option", { value: String(s.value) }, [s.label]));
  }

  scopeSelect.addEventListener("change", () => requestTargets());
  refreshBtn.addEventListener("click", () => requestTargets());
  presetSelect.addEventListener("change", () => applyPreset(presetSelect.value));
  savePresetBtn.addEventListener("click", () =>
    vscode.postMessage({ type: "savePreset", name: presetSelect.value, targets: mapping() }),
  );
  deletePresetBtn.addEventListener("click", () => {
    if (presetSelect.value) {
      vscode.postMessage({ type: "deletePreset", name: presetSelect.value });
    }
  });
  allIpBtn.addEventListener("click", () => {
    for (const row of state.rows.values()) {
      row.ip.value = allIp.value.trim();
    }
    validate();
  });
  allIp.addEventListener("input", () => updateActions());
  loopsInput.addEventListener("input", () => updateActions());
  startBtn.addEventListener("click", () => start());
  stopBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "stop" });
    statusText.textContent = "Stopping…";
  });
  allowBtn.addEventListener("click", () => vscode.postMessage({ type: "openSetting" }));

  // ------------------------------------------------------------------ messages

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    if (msg.type === "init") {
      title.textContent = msg.title;
      state.filter = msg.filter ?? "";
      state.remembered = msg.destinations ?? {};
      setConfig(msg);
      const o = msg.options ?? {};
      setSpeed(typeof o.speed === "number" ? o.speed : 1);
      loopsInput.value = String(o.loops ?? 1);
      scopeSelect.value = o.scope === "filter" && state.filter ? "filter" : "all";
      updateScope();
      state.running = !!msg.running;
      requestTargets();
    } else if (msg.type === "loading") {
      state.loading = true;
      statusText.textContent = msg.text;
      updateActions();
    } else if (msg.type === "targets") {
      state.loading = false;
      showTargets(msg.targets, msg.duration);
    } else if (msg.type === "filter") {
      state.filter = msg.filter ?? "";
      const was = scopeSelect.value;
      updateScope();
      if (was === "filter" && !state.running) {
        requestTargets();
      }
    } else if (msg.type === "config") {
      setConfig(msg);
    } else if (msg.type === "started") {
      started();
    } else if (msg.type === "progress") {
      progress(msg.progress);
    } else if (msg.type === "done") {
      done(msg.result);
    } else if (msg.type === "error") {
      failed(msg);
    }
  });

  /** @param {{presets?: Preset[], allowPublic?: boolean, selected?: string}} msg */
  function setConfig(msg) {
    state.presets = msg.presets ?? [];
    state.allowPublic = !!msg.allowPublic;
    const keep = msg.selected ?? presetSelect.value;
    presetSelect.replaceChildren(h("option", { value: "" }, ["None"]));
    for (const p of state.presets) {
      presetSelect.append(h("option", { value: p.name }, [p.name]));
    }
    presetSelect.value = state.presets.some((p) => p.name === keep) ? keep : "";
    if (state.allowPublic) {
      allowBtn.classList.add("hidden");
    }
    updateActions();
  }

  /** @param {number} speed */
  function setSpeed(speed) {
    if (!SPEEDS.some((s) => s.value === speed)) {
      speedSelect.append(h("option", { value: String(speed) }, [`${speed}×`]));
    }
    speedSelect.value = String(speed);
  }

  function updateScope() {
    const opt = /** @type {HTMLOptionElement} */ (scopeSelect.options[1]);
    opt.disabled = !state.filter;
    opt.textContent = state.filter ? `Displayed packets (${state.filter})` : "Displayed packets";
    if (!state.filter) {
      scopeSelect.value = "all";
    }
  }

  function requestTargets() {
    if (state.running) {
      return;
    }
    hideNotice();
    vscode.postMessage({ type: "targets", scope: scopeSelect.value });
  }

  // ------------------------------------------------------------------ the targets

  /** @param {Target[]} targets @param {number} duration */
  function showTargets(targets, duration) {
    state.targets = targets;
    state.rows.clear();
    if (!targets.length) {
      tableBox.replaceChildren();
      statusText.textContent =
        "Nothing to replay: no client sends TCP or UDP data in these packets.";
      updateActions();
      return;
    }
    const columns = [
      ["Replay", ""],
      ["Recorded target", ""],
      ["Protocol", ""],
      ["Connections", "num"],
      ["Packets", "num"],
      ["Bytes", "num"],
      ["Destination IP", ""],
      ["Port", ""],
      ["Sent", "num"],
      ["Received", "num"],
      ["Result", ""],
    ];
    const head = h(
      "tr",
      {},
      columns.map(([label, cls]) => h("th", { scope: "col", class: cls }, [label])),
    );
    const body = h("tbody");
    for (const t of targets) {
      const dest = state.remembered[t.key] ?? { ip: "127.0.0.1", port: t.port };
      const use = /** @type {HTMLInputElement} */ (
        h("input", { type: "checkbox", "aria-label": `Replay ${t.key}` })
      );
      use.checked = true;
      const ip = /** @type {HTMLInputElement} */ (
        h("input", {
          type: "text",
          class: "replay-ip",
          spellcheck: "false",
          "aria-label": `Destination IP for ${t.key}`,
        })
      );
      ip.value = dest.ip;
      const port = /** @type {HTMLInputElement} */ (
        h("input", {
          type: "text",
          inputmode: "numeric",
          class: "replay-port",
          "aria-label": `Destination port for ${t.key}`,
        })
      );
      port.value = String(dest.port);
      const notes = [];
      if (t.retransmissions) {
        notes.push(`${t.retransmissions} retransmitted (sent once)`);
      }
      if (t.gaps) {
        notes.push(`${t.gaps} ${t.gaps === 1 ? "gap" : "gaps"} (data missing from the capture)`);
      }
      const sent = h("td", { class: "num" });
      const received = h("td", { class: "num" });
      const result = h("td", { class: "wrap" }, [notes.join(", ")]);
      const packets = h("td", { class: "num" }, [t.packets.toLocaleString()]);
      if (notes.length) {
        packets.title = notes.join("\n");
      }
      const tr = /** @type {HTMLTableRowElement} */ (
        h("tr", { "data-key": t.key }, [
          h("td", {}, [use]),
          h("td", {}, [t.key]),
          h("td", {}, [t.protocol]),
          h("td", { class: "num" }, [t.connections.toLocaleString()]),
          packets,
          h("td", { class: "num", title: `${t.bytes.toLocaleString()} bytes` }, [
            lib.formatBytes(t.bytes),
          ]),
          h("td", {}, [ip]),
          h("td", {}, [port]),
          sent,
          received,
          result,
        ])
      );
      tr.addEventListener("click", () => select(t.key));
      for (const input of [use, ip, port]) {
        input.addEventListener("input", () => validate());
        input.addEventListener("focus", () => select(t.key));
      }
      state.rows.set(t.key, { tr, use, ip, port, sent, received, result });
      body.append(tr);
    }
    const table = h("table", { class: "stats replay", "aria-label": "Recorded targets" }, [
      h("thead", {}, [head]),
      body,
    ]);
    tableBox.replaceChildren(table);
    const n = targets.length;
    statusText.textContent =
      `${n} recorded ${n === 1 ? "target" : "targets"}, ` +
      `${lib.formatDuration(duration ?? 0)} of recorded traffic.`;
    if (presetSelect.value) {
      applyPreset(presetSelect.value);
    }
    validate();
  }

  /** @param {string} name */
  function applyPreset(name) {
    const preset = state.presets.find((p) => p.name === name);
    if (!preset || !state.targets) {
      updateActions();
      return;
    }
    const dests = lib.presetDestinations(preset, state.targets);
    for (const [key, row] of state.rows) {
      const dest = dests[key];
      row.use.checked = !!dest;
      if (dest) {
        row.ip.value = dest.ip;
        row.port.value = String(dest.port);
      }
    }
    const matched = Object.keys(dests).length;
    statusText.textContent =
      `Preset "${name}": ${matched} of ${state.targets.length} recorded ` +
      `${state.targets.length === 1 ? "target" : "targets"} matched.`;
    validate();
  }

  /** @param {string} key */
  function select(key) {
    state.selected = key;
    for (const [k, row] of state.rows) {
      row.tr.classList.toggle("selected", k === key);
    }
  }

  /** @returns {Record<string, Destination>} the checked rows' destinations */
  function mapping() {
    /** @type {Record<string, Destination>} */
    const out = {};
    for (const [key, row] of state.rows) {
      const port = lib.replayPort(row.port.value);
      if (
        row.use.checked &&
        port !== null &&
        !lib.replayDestinationProblem(row.ip.value, row.port.value)
      ) {
        out[key] = { ip: row.ip.value.trim(), port };
      }
    }
    return out;
  }

  /** Mark the checked rows whose destination can't be used; returns the first problem. */
  function validate() {
    let first = "";
    for (const [key, row] of state.rows) {
      const ipProblem = row.use.checked ? lib.replayDestinationProblem(row.ip.value, "1") : "";
      const portProblem =
        row.use.checked && lib.replayPort(row.port.value) === null
          ? "Enter a port between 1 and 65535"
          : "";
      row.ip.setAttribute("aria-invalid", String(!!ipProblem));
      row.port.setAttribute("aria-invalid", String(!!portProblem));
      row.ip.classList.toggle("invalid", !!ipProblem);
      row.port.classList.toggle("invalid", !!portProblem);
      row.ip.title = ipProblem;
      row.port.title = portProblem;
      if (!first && (ipProblem || portProblem)) {
        first = `${key}: ${ipProblem || portProblem}`;
      }
    }
    updateActions(first);
    return first;
  }

  function loops() {
    const n = Number(loopsInput.value);
    return Number.isInteger(n) && n >= 1 && n <= 1000 ? n : null;
  }

  /** @param {string} [problem] */
  function updateActions(problem = "") {
    const chosen = Object.keys(mapping()).length;
    const why = state.running
      ? "A replay is running"
      : state.loading
        ? "Finding the recorded targets…"
        : problem ||
          (loops() === null
            ? "Loops must be a whole number from 1 to 1000"
            : chosen
              ? ""
              : "Choose at least one recorded target");
    startBtn.toggleAttribute("disabled", !!why);
    startBtn.title = why || "Replay the checked targets";
    stopBtn.toggleAttribute("disabled", !state.running);
    loopsInput.setAttribute("aria-invalid", String(loops() === null));
    for (const el of [
      scopeSelect,
      presetSelect,
      refreshBtn,
      allIp,
      allIpBtn,
      speedSelect,
      loopsInput,
    ]) {
      el.toggleAttribute("disabled", state.running);
    }
    savePresetBtn.toggleAttribute("disabled", state.running || !chosen);
    deletePresetBtn.toggleAttribute("disabled", state.running || !presetSelect.value);
    for (const row of state.rows.values()) {
      for (const input of [row.use, row.ip, row.port]) {
        input.toggleAttribute("disabled", state.running);
      }
    }
  }

  // ------------------------------------------------------------------ the replay

  function start() {
    const n = loops();
    if (validate() || n === null) {
      return;
    }
    state.loops = n;
    hideNotice();
    statusText.textContent = "Starting the replay…";
    vscode.postMessage({
      type: "start",
      targets: mapping(),
      speed: Number(speedSelect.value),
      loops: n,
      scope: scopeSelect.value,
    });
  }

  function started() {
    state.running = true;
    log.replaceChildren();
    for (const row of state.rows.values()) {
      row.sent.textContent = "";
      row.received.textContent = "";
      row.result.textContent = row.use.checked ? "Waiting…" : "Not replayed";
    }
    bar.classList.remove("hidden");
    setFraction(null);
    statusText.textContent = "Starting the replay…";
    updateActions();
  }

  /** @param {number | null} fraction */
  function setFraction(fraction) {
    bar.classList.toggle("indeterminate", fraction === null);
    if (fraction === null) {
      bar.removeAttribute("aria-valuenow");
      fill.style.width = "";
    } else {
      const pct = Math.round(fraction * 100);
      bar.setAttribute("aria-valuenow", String(pct));
      fill.style.width = `${pct}%`;
    }
  }

  /** @param {any} p */
  function progress(p) {
    if (!state.running || p.phase !== "replay") {
      return;
    }
    setFraction(typeof p.fraction === "number" ? p.fraction : null);
    statusText.textContent = lib.replayStatusText(p, state.loops);
    showStats(p.targets ?? []);
    appendLog(p.log ?? []);
  }

  /** @param {Stats[]} stats */
  function showStats(stats) {
    for (const s of stats) {
      const row = state.rows.get(s.key);
      const target = state.targets?.find((t) => t.key === s.key);
      if (!row || !target) {
        continue;
      }
      row.sent.textContent = lib.formatBytes(s.bytes);
      row.sent.title = `${s.bytes.toLocaleString()} bytes`;
      row.received.textContent = lib.formatBytes(s.received);
      row.received.title = `${s.received.toLocaleString()} bytes`;
      row.result.textContent = lib.replayOutcome(s, target.proto);
      row.result.classList.toggle("replay-failed", s.errorCount > 0);
    }
  }

  /** @param {{time: number, level: string, text: string, target?: string}[]} lines */
  function appendLog(lines) {
    for (const line of lines) {
      const item = h("li", { class: line.level === "error" ? "log-error" : "" }, [
        h("span", { class: "log-time" }, [`${line.time.toFixed(3)} s`]),
        ...(line.target ? [h("span", { class: "log-target" }, [line.target])] : []),
        h("span", {}, [line.text]),
      ]);
      log.append(item);
    }
    while (log.childElementCount > MAX_LOG_LINES) {
      log.firstElementChild?.remove();
    }
    if (lines.length) {
      log.lastElementChild?.scrollIntoView({ block: "nearest" });
    }
  }

  /** @param {any} result */
  function done(result) {
    state.running = false;
    bar.classList.add("hidden");
    showStats(result.targets);
    appendLog(result.log ?? []);
    for (const row of state.rows.values()) {
      if (row.result.textContent === "Waiting…") {
        row.result.textContent = "Nothing sent";
      }
    }
    statusText.textContent = lib.replaySummary(result, state.loops);
    updateActions();
  }

  /** @param {{where: string, message: string, cancelled?: boolean, target?: string, publicTarget?: boolean}} msg */
  function failed(msg) {
    if (msg.where === "replay") {
      state.running = false;
      bar.classList.add("hidden");
    } else {
      state.loading = false;
    }
    if (msg.cancelled) {
      statusText.textContent = "Cancelled.";
    } else {
      statusText.textContent = msg.where === "replay" ? "The replay didn't start." : "";
      noticeText.textContent = msg.message;
      allowBtn.classList.toggle("hidden", !msg.publicTarget || state.allowPublic);
      notice.classList.remove("hidden");
      const row = msg.target ? state.rows.get(msg.target) : undefined;
      if (row) {
        select(/** @type {string} */ (msg.target));
        row.ip.focus();
      }
    }
    updateActions();
  }

  function hideNotice() {
    notice.classList.add("hidden");
    allowBtn.classList.add("hidden");
  }

  // ------------------------------------------------------------------ row menu

  /** @param {string} text */
  const copy = (text) => vscode.postMessage({ type: "copy", text });

  kit.rowMenu(tableBox, {
    rows: "tbody tr",
    select: (/** @type {HTMLElement} */ tr) => select(tr.dataset.key ?? ""),
    entries: (/** @type {HTMLElement} */ tr) => {
      const t = state.targets?.find((x) => x.key === tr.dataset.key);
      const row = t && state.rows.get(t.key);
      if (!t || !row) {
        return null;
      }
      const dest = `${row.ip.value.trim()}:${row.port.value.trim()}`;
      return [
        {
          label: `Go to Packet ${t.firstFrame}`,
          icon: "go-to-file",
          action: () => vscode.postMessage({ type: "goto", frame: t.firstFrame }),
        },
        "-",
        {
          label: "Copy",
          icon: "copy",
          children: [
            { label: "Recorded Target", hint: t.key, action: () => copy(t.key) },
            { label: "Destination", hint: dest, action: () => copy(dest) },
          ],
        },
      ];
    },
  });

  updateActions();
  vscode.postMessage({ type: "ready" });
})();
