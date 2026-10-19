// @ts-check
/**
 * Follow-stream panel: the reassembled payload of one conversation, colored
 * by direction, with a direction filter, ASCII / hex dump / raw views,
 * search, stream stepping, "filter to / out this stream" and save. Payload is
 * untrusted and only ever inserted with textContent (search matches are
 * <mark> elements holding text nodes).
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  /** Characters rendered at most; the rest is available via "Save as…". */
  const RENDER_BUDGET = 2_000_000;
  /** Search matches highlighted at most. */
  const MAX_MATCHES = 10_000;

  const state = {
    /** @type {any} */ result: null,
    label: "",
    /** @type {"both" | 0 | 1} */ dir: "both",
    /** @type {"ascii" | "hex" | "raw"} */ format: "ascii",
    query: "",
    /** The highlighted matches, in order, and the current one. @type {HTMLElement[]} */
    matches: [],
    current: -1,
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

  const title = h("h1", { class: "panel-title" }, ["Follow Stream"]);
  const legend = h("div", { class: "follow-legend" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" });
  const status = h("div", { class: "status", role: "status" }, ["Loading…"]);
  const notice = h("div", { class: "notice hidden", role: "alert" });
  const body = h("div", { class: "follow-body" });
  app.append(title, legend, toolbar, notice, status, body);

  const dirSelect = /** @type {HTMLSelectElement} */ (h("select", { "aria-label": "Direction" }));
  const formatSelect = /** @type {HTMLSelectElement} */ (
    h("select", { "aria-label": "Show data as" })
  );
  for (const [value, label] of [
    ["ascii", "ASCII"],
    ["hex", "Hex dump"],
    ["raw", "Raw (hex)"],
  ]) {
    formatSelect.append(h("option", { value }, [label]));
  }
  const streamInput = /** @type {HTMLInputElement} */ (
    h("input", { type: "number", min: "0", "aria-label": "Stream number" })
  );
  const prev = h(
    "button",
    {
      type: "button",
      class: "secondary",
      title: "Previous stream",
      "aria-label": "Previous stream",
    },
    [icon("chevron-left")],
  );
  const next = h(
    "button",
    { type: "button", class: "secondary", title: "Next stream", "aria-label": "Next stream" },
    [icon("chevron-right")],
  );
  const filterBtn = h(
    "button",
    { type: "button", title: "Apply a display filter for this stream in the capture" },
    ["Filter to Stream"],
  );
  const filterOutBtn = h(
    "button",
    {
      type: "button",
      class: "secondary",
      title: "Hide this stream in the capture (within the display filter applied)",
    },
    ["Filter Out This Stream"],
  );
  const saveBtn = h("button", { type: "button", class: "secondary" }, ["Save as…"]);
  toolbar.append(
    h("label", {}, ["Show ", dirSelect]),
    h("label", {}, ["as ", formatSelect]),
    h("label", {}, ["Stream ", streamInput]),
    prev,
    next,
    h("span", { class: "spacer" }),
    filterBtn,
    filterOutBtn,
    saveBtn,
  );

  // Search: Enter / Shift+Enter (or the arrows) step through the matches.
  const findInput = /** @type {HTMLInputElement} */ (
    h("input", {
      type: "search",
      id: "follow-find",
      placeholder: "Find in stream",
      "aria-label": "Find in stream",
    })
  );
  const findPrev = h(
    "button",
    {
      type: "button",
      class: "icon",
      id: "follow-find-prev",
      title: "Previous match (Shift+Enter)",
      "aria-label": "Previous match",
    },
    [icon("arrow-up")],
  );
  const findNext = h(
    "button",
    {
      type: "button",
      class: "icon",
      id: "follow-find-next",
      title: "Next match (Enter)",
      "aria-label": "Next match",
    },
    [icon("arrow-down")],
  );
  const findCount = h("span", {
    class: "find-count",
    id: "follow-find-count",
    "aria-live": "polite",
  });
  const findBar = h("div", { class: "toolbar", role: "search" }, [
    findInput,
    findPrev,
    findNext,
    findCount,
  ]);
  toolbar.after(findBar);

  dirSelect.addEventListener("change", () => {
    state.dir = dirSelect.value === "both" ? "both" : dirSelect.value === "0" ? 0 : 1;
    renderBody();
  });
  formatSelect.addEventListener("change", () => {
    state.format = /** @type {any} */ (formatSelect.value);
    renderBody();
  });
  /** @param {number} n */
  const goStream = (n) => {
    if (Number.isInteger(n) && n >= 0) {
      vscode.postMessage({ type: "stream", stream: n });
    }
  };
  streamInput.addEventListener("change", () => goStream(Number(streamInput.value)));
  prev.addEventListener("click", () => state.result && goStream(state.result.stream - 1));
  next.addEventListener("click", () => state.result && goStream(state.result.stream + 1));
  filterOutBtn.addEventListener("click", () => {
    if (state.result) {
      vscode.postMessage({
        type: "filterOut",
        expr: lib.streamFilter(state.result.proto, state.result.stream),
      });
    }
  });
  let findTimer = 0;
  findInput.addEventListener("input", () => {
    window.clearTimeout(findTimer);
    findTimer = window.setTimeout(() => {
      state.query = findInput.value;
      renderBody();
    }, 150);
  });
  findInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      window.clearTimeout(findTimer);
      if (findInput.value !== state.query) {
        state.query = findInput.value; // typed faster than the debounce
        renderBody();
      } else {
        step(e.shiftKey ? -1 : 1);
      }
    } else if (e.key === "Escape" && findInput.value) {
      e.preventDefault();
      findInput.value = state.query = "";
      renderBody();
    }
  });
  findPrev.addEventListener("click", () => step(-1));
  findNext.addEventListener("click", () => step(1));
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
      e.preventDefault();
      findInput.focus();
      findInput.select();
    }
  });
  filterBtn.addEventListener("click", () => {
    if (state.result) {
      vscode.postMessage({
        type: "filter",
        expr: lib.streamFilter(state.result.proto, state.result.stream),
        apply: true,
      });
    }
  });
  saveBtn.addEventListener("click", () => {
    if (!state.result) {
      return;
    }
    const raw = state.format === "raw";
    vscode.postMessage({
      type: "save",
      dir: state.dir,
      format: raw ? "raw" : "text",
      text: raw ? undefined : renderText(Infinity).text,
    });
  });

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    if (msg.type === "loading") {
      status.textContent = "Running tshark…";
      notice.classList.add("hidden");
    } else if (msg.type === "error") {
      status.textContent = "";
      notice.textContent = msg.message;
      notice.classList.add("error");
      notice.classList.remove("hidden");
    } else if (msg.type === "result") {
      state.result = msg.result;
      state.label = msg.label;
      render();
    }
  });

  function render() {
    const r = state.result;
    const [a, b] = r.nodes;
    title.textContent = `${state.label} stream ${r.stream}`;
    streamInput.value = String(r.stream);
    prev.toggleAttribute("disabled", r.stream <= 0);
    const total = r.bytes[0] + r.bytes[1];
    dirSelect.replaceChildren(
      h("option", { value: "both" }, [`Entire conversation (${total.toLocaleString()} bytes)`]),
      h("option", { value: "0" }, [`${a} → ${b} (${r.bytes[0].toLocaleString()} bytes)`]),
      h("option", { value: "1" }, [`${b} → ${a} (${r.bytes[1].toLocaleString()} bytes)`]),
    );
    dirSelect.value = String(state.dir);
    // Identity is spelled out, not left to color alone.
    legend.replaceChildren(
      h("span", { class: "dir0" }, [h("span", { class: "key" }), `${a || "?"} → ${b || "?"}`]),
      h("span", { class: "dir1" }, [h("span", { class: "key" }), `${b || "?"} → ${a || "?"}`]),
    );
    const notes = [];
    if (r.truncated) {
      notes.push("The stream is larger than the transfer limit; only its beginning is shown.");
    }
    if (r.hint) {
      notes.push(r.hint);
    }
    notice.classList.remove("error");
    notice.textContent = notes.join(" ");
    notice.classList.toggle("hidden", !notes.length);
    renderBody();
  }

  /**
   * Text for the current direction/format, split into segments.
   * @param {number} budget maximum characters
   */
  function renderText(budget) {
    const r = state.result;
    const parts = [];
    const offsets = [0, 0];
    let used = 0;
    let clipped = false;
    for (const seg of r.segments) {
      if (state.dir !== "both" && seg.dir !== state.dir) {
        continue;
      }
      const bytes = lib.hexToBytes(seg.hex);
      let text =
        state.format === "ascii"
          ? lib.bytesToAscii(bytes)
          : state.format === "hex"
            ? lib.hexDump(bytes, offsets[seg.dir])
            : seg.hex.replace(/(.{64})/g, "$1\n").trimEnd();
      offsets[seg.dir] += bytes.length;
      if (used + text.length > budget) {
        text = text.slice(0, Math.max(0, budget - used));
        clipped = true;
      }
      used += text.length;
      parts.push({ dir: seg.dir, text });
      if (clipped) {
        break;
      }
    }
    return {
      parts,
      clipped,
      text: parts.map((p) => p.text).join(state.format === "ascii" ? "" : "\n"),
    };
  }

  function renderBody() {
    if (!state.result) {
      return;
    }
    const { parts, clipped } = renderText(RENDER_BUDGET);
    const frag = document.createDocumentFragment();
    /** @type {HTMLElement[]} */
    const matches = [];
    for (const p of parts) {
      const pre = h("pre", { class: `segment dir${p.dir}` });
      const ranges = lib.findRanges(p.text, state.query, MAX_MATCHES - matches.length);
      let at = 0;
      for (const [start, end] of ranges) {
        const mark = h("mark", { class: "find-match" });
        mark.textContent = p.text.slice(start, end);
        pre.append(p.text.slice(at, start), mark);
        matches.push(mark);
        at = end;
      }
      pre.append(p.text.slice(at));
      frag.append(pre);
    }
    body.replaceChildren(frag);
    state.matches = matches;
    state.current = -1;
    step(1);
    const r = state.result;
    const segs = r.segments.length;
    status.textContent = segs
      ? `${segs} ${segs === 1 ? "segment" : "segments"}${clipped ? ` · showing the first ${RENDER_BUDGET.toLocaleString()} characters (save to get everything)` : ""}`
      : "No payload in this stream.";
    saveBtn.toggleAttribute("disabled", !segs);
  }

  /**
   * Make the next (1) or previous (-1) match the current one, wrapping around.
   * @param {1 | -1} delta
   */
  function step(delta) {
    const n = state.matches.length;
    state.matches[state.current]?.classList.remove("current");
    findPrev.toggleAttribute("disabled", n < 2);
    findNext.toggleAttribute("disabled", n < 2);
    if (!n) {
      state.current = -1;
      findCount.textContent = state.query ? "No matches" : "";
      return;
    }
    state.current = (state.current + delta + n) % n;
    const mark = state.matches[state.current];
    mark.classList.add("current");
    mark.scrollIntoView({ block: "center" });
    const total = n >= MAX_MATCHES ? `${MAX_MATCHES.toLocaleString()}+` : n.toLocaleString();
    findCount.textContent = `${(state.current + 1).toLocaleString()} of ${total}`;
  }

  vscode.postMessage({ type: "ready" });
})();
