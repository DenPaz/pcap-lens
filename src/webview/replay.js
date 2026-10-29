// @ts-check
/**
 * Replay to Service panel: the open capture's recorded targets (the server
 * ends of TCP connections and UDP flows), an IP and port for each, presets,
 * setup files, speed, loops, jitter and UDP loss; then the replay's live
 * counts per target, a log and a summary. Other captures (played one after
 * another or merged by time) sit in a collapsed "More captures…" section.
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
   * @typedef {{name: string, file: string | null, targets: number, packets: number,
   *   bytes: number, duration: number, error: string | null}} SourceInfo
   * @typedef {{path: string, enabled: boolean, missing?: boolean, info?: SourceInfo}} CaptureFile
   * @typedef {{ip: string, port: number, enabled: boolean}} SetupTarget
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
    /** The loops of the running (or last) replay (0: until stopped). */
    loops: 1,
    /** The open capture plays too. */
    includeOpen: true,
    /** How many of `files` play before the open capture (0: it plays first). */
    openAt: 0,
    /** @type {SourceInfo | null} */ openInfo: null,
    /** @type {CaptureFile[]} other captures, in the order they play */ files: [],
    /** @type {Record<string, SetupTarget>} a loaded setup's destinations, kept for later lists */
    setupTargets: {},
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
  const loadSetupBtn = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "replay-load-setup" }, ["Load Setup…"]),
    "folder-opened",
  );
  const saveSetupBtn = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "replay-save-setup" }, ["Save Setup…"]),
    "save-as",
  );
  const toolbar = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Targets" }, [
    h("label", {}, ["Packets ", scopeSelect]),
    h("label", {}, ["Preset ", presetSelect]),
    savePresetBtn,
    deletePresetBtn,
    h("span", { class: "spacer" }),
    loadSetupBtn,
    saveSetupBtn,
    refreshBtn,
  ]);
  const capturesBox = h("div", { class: "replay-captures" });
  const addCapturesBtn = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "replay-add-captures" }, [
      "Add Captures…",
    ]),
    "add",
  );
  const addFolderBtn = kit.withIcon(
    h("button", { type: "button", class: "secondary", id: "replay-add-folder" }, ["Add Folder…"]),
    "new-folder",
  );
  const orderSelect = /** @type {HTMLSelectElement} */ (
    h("select", { id: "replay-order", "aria-label": "Order of the captures" }, [
      h("option", { value: "sequence" }, ["One after another"]),
      h("option", { value: "merged" }, ["Merged by recorded time"]),
    ])
  );
  const capturesBar = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Captures" }, [
    addCapturesBtn,
    addFolderBtn,
    h("label", {}, ["Play ", orderSelect]),
  ]);
  // Other captures: folded away, so the panel shows the open capture alone until asked.
  const moreCount = h("span", { class: "replay-dim", id: "replay-more-count" });
  const more = /** @type {HTMLDetailsElement} */ (
    h("details", { id: "replay-more", class: "replay-more" }, [
      h("summary", {}, ["More captures…", moreCount]),
      capturesBar,
      capturesBox,
    ])
  );
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
  const forever = /** @type {HTMLInputElement} */ (
    h("input", { id: "replay-forever", type: "checkbox" })
  );
  const jitterInput = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "replay-jitter",
      type: "number",
      min: "0",
      max: "60000",
      value: "0",
      "aria-label": "Jitter in milliseconds",
      title: "Each packet's pause moves by a random amount within ± this many ms",
    })
  );
  const lossInput = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "replay-loss",
      type: "number",
      min: "0",
      max: "100",
      step: "any",
      value: "0",
      "aria-label": "UDP loss in percent",
      title:
        "This share of UDP datagrams is left out at random. TCP data is always sent: the network stack would send lost data again.",
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
    h("label", {}, [forever, " Until stopped"]),
    h("label", {}, ["Jitter (ms) ", jitterInput]),
    h("label", {}, ["UDP loss (%) ", lossInput]),
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
  // (Focusable: it scrolls, and keyboard users must reach what it holds.)
  const log = h("ol", {
    id: "replay-log",
    class: "replay-log",
    "aria-label": "Replay log",
    tabindex: "0",
  });
  app.append(title, intro, toolbar, more, tableBox, options, notice, status, bar, logHead, log);

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
  for (const input of [loopsInput, forever, jitterInput, lossInput, speedSelect, orderSelect]) {
    input.addEventListener("input", () => updateActions());
  }
  orderSelect.addEventListener("change", () => showDuration());
  addCapturesBtn.addEventListener("click", () => vscode.postMessage({ type: "addCaptures" }));
  addFolderBtn.addEventListener("click", () => vscode.postMessage({ type: "addFolder" }));
  loadSetupBtn.addEventListener("click", () => vscode.postMessage({ type: "loadSetup" }));
  saveSetupBtn.addEventListener("click", () =>
    vscode.postMessage({ type: "saveSetup", setup: currentSetup() }),
  );
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
      setOptions(msg.options ?? {});
      state.running = !!msg.running;
      renderCaptures();
      requestTargets();
    } else if (msg.type === "loading") {
      state.loading = true;
      statusText.textContent = msg.text;
      updateActions();
    } else if (msg.type === "targets") {
      state.loading = false;
      showSources(msg.sources ?? []);
      showTargets(msg.targets, msg);
    } else if (msg.type === "filesAdded") {
      addFiles(msg.files ?? [], !!msg.enabled);
    } else if (msg.type === "setup") {
      applySetup(msg);
    } else if (msg.type === "setupSaved") {
      statusText.textContent = `Setup saved as ${msg.name}.`;
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

  /** @param {{speed?: number, loops?: number, scope?: string, order?: string, jitter?: number, loss?: number}} o */
  function setOptions(o) {
    setSpeed(typeof o.speed === "number" ? o.speed : 1);
    forever.checked = o.loops === 0;
    loopsInput.value = String(o.loops ? o.loops : 1);
    orderSelect.value = o.order === "merged" ? "merged" : "sequence";
    jitterInput.value = String(o.jitter ?? 0);
    lossInput.value = String(o.loss ?? 0);
    scopeSelect.value = o.scope === "filter" && state.filter ? "filter" : "all";
    updateScope();
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

  /** @param {CaptureFile} f */
  const plays = (f) => f.enabled && !f.missing;

  /** The other captures that play, in order. */
  function playedFiles() {
    return state.files.filter(plays).map((f) => f.path);
  }

  /** How many of the captures that play come before the open one (the backend's `openAt`). */
  function playedOpenAt() {
    return state.files.slice(0, state.openAt).filter(plays).length;
  }

  function requestTargets() {
    if (state.running) {
      return;
    }
    hideNotice();
    vscode.postMessage({
      type: "targets",
      scope: scopeSelect.value,
      capture: state.includeOpen,
      files: playedFiles(),
      openAt: playedOpenAt(),
    });
  }

  // ------------------------------------------------------------------ the captures

  /** @param {string} file */
  function baseName(file) {
    return file.split(/[\\/]/).pop() || file;
  }

  /** @param {SourceInfo | undefined | null} info @param {boolean} played @param {boolean} [missing] */
  function sourceText(info, played, missing) {
    if (missing) {
      return "File not found";
    }
    if (!info) {
      return played ? "Reading…" : "Not read yet (check it to read it)";
    }
    if (info.error) {
      return `Can't be read: ${info.error}`;
    }
    const n = info.targets;
    return (
      `${n} ${n === 1 ? "target" : "targets"} · ${info.packets.toLocaleString()} ` +
      `${info.packets === 1 ? "packet" : "packets"} · ${lib.formatDuration(info.duration)}`
    );
  }

  /**
   * @param {string} label @param {string} codicon @param {() => void} action
   * @param {boolean} disabled
   */
  function iconButton(label, codicon, action, disabled) {
    const btn = h("button", { type: "button", class: "icon", title: label, "aria-label": label }, [
      kit.icon(codicon),
    ]);
    btn.toggleAttribute("disabled", disabled || state.running);
    btn.addEventListener("click", action);
    return btn;
  }

  /** The open capture's name, as the title gives it. */
  function openName() {
    return title.textContent?.replace(/^Replay to Service · /, "") || "Open capture";
  }

  /**
   * The captures list in play order: the other captures, with the open one
   * (`null`) at `state.openAt`.
   * @returns {(CaptureFile | null)[]}
   */
  function listed() {
    const items = /** @type {(CaptureFile | null)[]} */ ([...state.files]);
    items.splice(Math.min(state.openAt, state.files.length), 0, null);
    return items;
  }

  function renderCaptures() {
    const body = h("tbody");
    const items = listed();
    items.forEach((file, pos) => {
      const name = file ? baseName(file.path) : openName();
      const use = /** @type {HTMLInputElement} */ (
        h("input", {
          type: "checkbox",
          "aria-label": file ? `Replay ${name}` : "Replay the open capture",
        })
      );
      use.checked = file ? file.enabled && !file.missing : state.includeOpen;
      use.disabled = state.running || !!file?.missing;
      use.addEventListener("change", () => {
        if (file) {
          file.enabled = use.checked;
        } else {
          state.includeOpen = use.checked;
        }
        captureChanged();
      });
      const info = h("td", { class: "wrap" }, [
        file
          ? sourceText(file.info, file.enabled, file.missing)
          : sourceText(state.openInfo, state.includeOpen),
      ]);
      info.classList.toggle("replay-failed", !!file?.missing || !!file?.info?.error);
      const actions = [
        iconButton(`Play ${name} earlier`, "arrow-up", () => moveCapture(pos, -1), pos === 0),
        iconButton(
          `Play ${name} later`,
          "arrow-down",
          () => moveCapture(pos, 1),
          pos === items.length - 1,
        ),
      ];
      if (file) {
        actions.push(
          iconButton(`Remove ${name}`, "close", () => removeFile(state.files.indexOf(file)), false),
        );
      }
      body.append(
        h("tr", { "data-capture": file ? file.path : "" }, [
          h("td", {}, [use]),
          file
            ? h("td", { title: file.path }, [name])
            : h("td", {}, [name, h("span", { class: "replay-dim" }, [" (open in the viewer)"])]),
          info,
          h("td", { class: "replay-capture-actions" }, actions),
        ]),
      );
    });
    const table = h("table", { class: "stats replay-capture-list", "aria-label": "Captures" }, [
      h("thead", {}, [
        h("tr", {}, [
          h("th", { scope: "col" }, ["Replay"]),
          h("th", { scope: "col" }, ["Capture"]),
          h("th", { scope: "col" }, ["Recorded"]),
          h("th", { scope: "col" }, [h("span", { class: "visually-hidden" }, ["Actions"])]),
        ]),
      ]),
      body,
    ]);
    capturesBox.replaceChildren(table);
    moreCount.textContent = moreText();
    updateActions();
  }

  /** What the folded section changes, so it isn't missed while closed. */
  function moreText() {
    const added = state.files.length;
    if (!added && state.includeOpen) {
      return "";
    }
    const parts = [];
    if (added) {
      const played = playedFiles().length;
      parts.push(`${added} added, ${played} ${played === 1 ? "plays" : "play"}`);
    }
    const before = playedOpenAt();
    if (!state.includeOpen) {
      parts.push("the open capture is left out");
    } else if (before) {
      parts.push(`the open capture plays after ${before} ${before === 1 ? "other" : "others"}`);
    }
    return ` (${parts.join("; ")})`;
  }

  function captureChanged() {
    renderCaptures();
    requestTargets();
  }

  /**
   * Move the capture at `pos` in the list (the open one too) by `delta`. The
   * targets stay: they are listed by their first recorded data, whatever the
   * order the captures play in.
   * @param {number} pos @param {number} delta
   */
  function moveCapture(pos, delta) {
    const items = listed();
    const to = pos + delta;
    if (to < 0 || to >= items.length) {
      return;
    }
    const [item] = items.splice(pos, 1);
    items.splice(to, 0, item);
    state.openAt = items.indexOf(null);
    state.files = /** @type {CaptureFile[]} */ (items.filter((f) => f !== null));
    renderCaptures();
  }

  /** @param {number} i */
  function removeFile(i) {
    const [file] = state.files.splice(i, 1);
    if (i < state.openAt) {
      state.openAt -= 1;
    }
    renderCaptures();
    if (file?.enabled) {
      requestTargets();
    }
  }

  /** @param {string[]} files @param {boolean} enabled */
  function addFiles(files, enabled) {
    let added = 0;
    for (const file of files) {
      if (!state.files.some((f) => f.path === file)) {
        state.files.push({ path: file, enabled });
        added += 1;
      }
    }
    renderCaptures();
    if (added && enabled) {
      requestTargets();
    } else if (added) {
      statusText.textContent = `${added} ${added === 1 ? "capture" : "captures"} added: check the ones to replay.`;
    }
  }

  /** @param {SourceInfo[]} sources */
  function showSources(sources) {
    state.openInfo = sources.find((s) => s.file === null) ?? state.openInfo;
    for (const file of state.files) {
      const info = sources.find((s) => s.file === file.path);
      if (info) {
        file.info = info;
      }
    }
    renderCaptures();
  }

  /** How many captures play. */
  function playedCount() {
    return (state.includeOpen ? 1 : 0) + playedFiles().length;
  }

  // ------------------------------------------------------------------ the targets

  /** The recorded time of what plays (one after another or merged), for the status line. */
  let recorded = { duration: 0, span: 0 };

  function showDuration() {
    if (!state.targets?.length || state.running) {
      return;
    }
    const n = state.targets.length;
    const merged = orderSelect.value === "merged" && playedCount() > 1;
    const time = merged ? recorded.span : recorded.duration;
    statusText.textContent =
      `${n} recorded ${n === 1 ? "target" : "targets"}, ` +
      `${lib.formatDuration(time ?? 0)} of recorded traffic` +
      (playedCount() > 1 ? (merged ? " (merged)." : " (one capture after another).") : ".");
  }

  /** @param {Target[]} targets @param {{duration?: number, span?: number}} times */
  function showTargets(targets, times) {
    state.targets = targets;
    state.rows.clear();
    recorded = { duration: times.duration ?? 0, span: times.span ?? 0 };
    if (!targets.length) {
      tableBox.replaceChildren();
      statusText.textContent = playedCount()
        ? "Nothing to replay: no client sends TCP or UDP data in these packets."
        : "Check at least one capture to replay.";
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
      const fromSetup = state.setupTargets[t.key];
      const dest = fromSetup ?? state.remembered[t.key] ?? { ip: "127.0.0.1", port: t.port };
      const use = /** @type {HTMLInputElement} */ (
        h("input", { type: "checkbox", "aria-label": `Replay ${t.key}` })
      );
      use.checked = fromSetup ? fromSetup.enabled : true;
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
    showDuration();
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

  /** The loops asked for (0: until stopped), or null when the box can't be read. */
  function loops() {
    if (forever.checked) {
      return 0;
    }
    const n = Number(loopsInput.value);
    return Number.isInteger(n) && n >= 1 && n <= 1000 ? n : null;
  }

  /** @param {HTMLInputElement} input @param {number} max */
  function numberIn(input, max) {
    const n = Number(input.value);
    return input.value.trim() !== "" && Number.isFinite(n) && n >= 0 && n <= max ? n : null;
  }

  /** The setup as the panel shows it (Save Setup…). */
  function currentSetup() {
    /** @type {Record<string, SetupTarget>} */
    const targets = { ...state.setupTargets };
    for (const [key, row] of state.rows) {
      const port = lib.replayPort(row.port.value);
      if (port !== null && row.ip.value.trim()) {
        targets[key] = { ip: row.ip.value.trim(), port, enabled: row.use.checked };
      }
    }
    return {
      includeOpen: state.includeOpen,
      openAt: state.openAt,
      captures: state.files.map((f) => ({ path: f.path, enabled: f.enabled })),
      targets,
      options: {
        speed: Number(speedSelect.value),
        loops: loops() ?? 1,
        scope: scopeSelect.value,
        order: orderSelect.value,
        jitter: numberIn(jitterInput, 60000) ?? 0,
        loss: numberIn(lossInput, 100) ?? 0,
      },
    };
  }

  /** @param {{name: string, setup: any, problems: string[], missing: string[]}} msg */
  function applySetup(msg) {
    const setup = msg.setup;
    state.includeOpen = setup.includeOpen;
    state.files = setup.captures.map((/** @type {{path: string, enabled: boolean}} */ c) => ({
      path: c.path,
      enabled: c.enabled,
      missing: msg.missing.includes(c.path),
    }));
    state.openAt = Math.min(setup.openAt ?? 0, state.files.length);
    state.setupTargets = setup.targets;
    presetSelect.value = ""; // (the setup's destinations, not a preset's)
    if (state.files.length || !state.includeOpen) {
      more.open = true;
    }
    setOptions(setup.options);
    renderCaptures();
    requestTargets();
    const notes = [
      ...msg.missing.map((m) => `${baseName(m)} wasn't found (${m})`),
      ...msg.problems,
    ];
    if (notes.length) {
      noticeText.textContent = `Loaded ${msg.name}, except: ${notes.join("; ")}.`;
      allowBtn.classList.add("hidden");
      notice.classList.remove("hidden");
    }
    statusText.textContent = `Loaded the setup ${msg.name}.`;
  }

  /** @param {string} [problem] */
  function updateActions(problem = "") {
    const chosen = Object.keys(mapping()).length;
    const paced = Number(speedSelect.value) > 0;
    const why = state.running
      ? "A replay is running"
      : state.loading
        ? "Finding the recorded targets…"
        : problem ||
          (!playedCount()
            ? "Check at least one capture to replay"
            : loops() === null
              ? "Loops must be a whole number from 1 to 1000"
              : paced && numberIn(jitterInput, 60000) === null
                ? "Jitter must be between 0 and 60,000 ms"
                : numberIn(lossInput, 100) === null
                  ? "UDP loss must be a percentage from 0 to 100"
                  : chosen
                    ? ""
                    : "Choose at least one recorded target");
    startBtn.toggleAttribute("disabled", !!why);
    startBtn.title = why || "Replay the checked targets";
    stopBtn.toggleAttribute("disabled", !state.running);
    loopsInput.setAttribute("aria-invalid", String(loops() === null));
    jitterInput.setAttribute("aria-invalid", String(numberIn(jitterInput, 60000) === null));
    lossInput.setAttribute("aria-invalid", String(numberIn(lossInput, 100) === null));
    for (const el of [
      scopeSelect,
      presetSelect,
      refreshBtn,
      allIp,
      allIpBtn,
      speedSelect,
      forever,
      lossInput,
      loadSetupBtn,
      saveSetupBtn,
      addCapturesBtn,
      addFolderBtn,
    ]) {
      el.toggleAttribute("disabled", state.running);
    }
    loopsInput.toggleAttribute("disabled", state.running || forever.checked);
    jitterInput.toggleAttribute("disabled", state.running || !paced);
    jitterInput.title = paced
      ? "Each packet's pause moves by a random amount within ± this many ms"
      : "No pauses: there is nothing to vary";
    orderSelect.toggleAttribute("disabled", state.running || playedCount() < 2);
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
      order: orderSelect.value,
      jitter: Number(speedSelect.value) > 0 ? (numberIn(jitterInput, 60000) ?? 0) : 0,
      loss: numberIn(lossInput, 100) ?? 0,
      capture: state.includeOpen,
      files: playedFiles(),
      openAt: playedOpenAt(),
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
    renderCaptures();
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
    renderCaptures();
    updateActions();
  }

  /** @param {{where: string, message: string, cancelled?: boolean, target?: string, publicTarget?: boolean}} msg */
  function failed(msg) {
    if (msg.where === "replay") {
      state.running = false;
      bar.classList.add("hidden");
      renderCaptures();
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
