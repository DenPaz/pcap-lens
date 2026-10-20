// @ts-check
/**
 * Show Packet Bytes panel (Wireshark's dialog): one field's bytes, decoded
 * (Base64, compressed, hex digits, percent-encoding, quoted-printable,
 * ROT13) and shown as text, a hex dump, a C or Rust array, YAML or an image,
 * from a start to an end byte, with search; saved raw or as shown. The bytes
 * are untrusted: text only ever goes in with textContent (search matches are
 * <mark> elements holding text nodes), an image only as a data: URL in <img>.
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
  /** Decompressed output stops here (a small field can expand a lot). */
  const MAX_DECOMPRESSED = 64 * 1024 * 1024;
  const DECODES = [
    ["none", "None"],
    ["base64", "Base64"],
    ["compressed", "Compressed (gzip, zlib, deflate)"],
    ["hex", "Hex digits"],
    ["percent", "Percent-encoding"],
    ["quoted-printable", "Quoted-printable"],
    ["rot13", "ROT13"],
  ];
  /** "Show as" choices: value, label, file extension when saved as text. */
  const VIEWS = [
    ["ascii", "ASCII", "txt"],
    ["ascii-control", "ASCII & control", "txt"],
    ["c", "C array", "c"],
    ["ebcdic", "EBCDIC", "txt"],
    ["hexdump", "Hex dump", "txt"],
    ["image", "Image", ""],
    ["latin1", "ISO 8859-1", "txt"],
    ["hex", "Raw (hex)", "txt"],
    ["rust", "Rust array", "rs"],
    ["utf-8", "UTF-8", "txt"],
    ["utf-16", "UTF-16", "txt"],
    ["yaml", "YAML", "yaml"],
  ];

  const state = {
    /** @type {{frame: number, field: string, label: string, hex: string} | null} */ field: null,
    decode: "none",
    view: "ascii",
    start: 0,
    /** Inclusive; -1 = the last byte. */
    end: -1,
    /** The decoded bytes (all of them; start/end cut what is shown). */
    decoded: new Uint8Array(0),
    error: "",
    /** What the decode did, for the status line (compression). */
    decodeNote: "",
    query: "",
    /** @type {HTMLElement[]} */ matches: [],
    current: -1,
    seq: 0,
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

  /** @param {string} label @param {string[][]} choices */
  const select = (label, choices) => {
    const node = /** @type {HTMLSelectElement} */ (h("select", { "aria-label": label }));
    for (const [value, text] of choices) {
      node.append(h("option", { value }, [text]));
    }
    return node;
  };

  const title = h("h1", { class: "panel-title" }, ["Packet Bytes"]);
  const subtitle = h("div", { class: "bytes-field" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" });
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const body = h("div", { class: "bytes-body" });
  app.append(title, subtitle, toolbar, notice, status, body);

  const decodeSelect = select("Decode as", DECODES);
  const viewSelect = select("Show as", VIEWS);
  const startInput = /** @type {HTMLInputElement} */ (
    h("input", {
      type: "number",
      min: "0",
      value: "0",
      id: "bytes-start",
      "aria-label": "Start byte",
    })
  );
  const endInput = /** @type {HTMLInputElement} */ (
    h("input", { type: "number", min: "0", id: "bytes-end", "aria-label": "End byte" })
  );
  const gotoBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Select this packet in the capture" },
    ["Go to Packet"],
  );
  const copyBtn = h("button", { type: "button", class: "secondary", title: "Copy what is shown" }, [
    "Copy",
  ]);
  const saveBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Save what is shown (text views) " },
    ["Save as…"],
  );
  const saveRawBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Save the decoded bytes from start to end" },
    ["Save Raw…"],
  );
  toolbar.append(
    h("label", {}, ["Decode as ", decodeSelect]),
    h("label", {}, ["Show as ", viewSelect]),
    h("label", {}, ["Start ", startInput]),
    h("label", {}, ["End ", endInput]),
    h("span", { class: "spacer" }),
    gotoBtn,
    copyBtn,
    saveBtn,
    saveRawBtn,
  );

  const findInput = /** @type {HTMLInputElement} */ (
    h("input", {
      type: "search",
      id: "bytes-find",
      placeholder: "Find",
      "aria-label": "Find in the bytes shown",
    })
  );
  const findPrev = h(
    "button",
    {
      type: "button",
      class: "icon",
      title: "Previous match (Shift+Enter)",
      "aria-label": "Previous match",
    },
    [icon("arrow-up")],
  );
  const findNext = h(
    "button",
    { type: "button", class: "icon", title: "Next match (Enter)", "aria-label": "Next match" },
    [icon("arrow-down")],
  );
  const findCount = h("span", { class: "find-count", "aria-live": "polite" });
  toolbar.after(
    h("div", { class: "toolbar", role: "search" }, [findInput, findPrev, findNext, findCount]),
  );

  decodeSelect.addEventListener("change", () => {
    state.decode = decodeSelect.value;
    void decode();
  });
  viewSelect.addEventListener("change", () => {
    state.view = viewSelect.value;
    renderBody();
  });
  for (const input of [startInput, endInput]) {
    input.addEventListener("change", () => {
      const max = Math.max(0, state.decoded.length - 1);
      const n = (/** @type {string} */ v, /** @type {number} */ fallback) =>
        Number.isInteger(Number(v)) && v !== "" ? Math.min(max, Math.max(0, Number(v))) : fallback;
      state.start = n(startInput.value, 0);
      state.end = Math.max(state.start, n(endInput.value, max));
      renderBody();
    });
  }
  gotoBtn.addEventListener("click", () => vscode.postMessage({ type: "goto" }));
  copyBtn.addEventListener("click", () => vscode.postMessage({ type: "copy", text: shownText() }));
  saveBtn.addEventListener("click", () =>
    vscode.postMessage({
      type: "save",
      text: shownText(),
      ext: VIEWS.find(([value]) => value === state.view)?.[2] || "txt",
    }),
  );
  saveRawBtn.addEventListener("click", () =>
    vscode.postMessage({ type: "save", base64: lib.bytesToBase64(shown()) }),
  );
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
        state.query = findInput.value;
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

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    if (msg.type === "show") {
      state.field = msg;
      state.start = 0;
      state.end = -1;
      title.textContent = `Packet Bytes · packet ${msg.frame}`;
      subtitle.textContent = msg.field ? `${msg.label} (${msg.field})` : msg.label;
      void decode();
    }
  });

  /** Gunzip / inflate in the browser (DecompressionStream), capped. @param {Uint8Array} bytes */
  async function decompress(bytes) {
    const format = lib.compressionFormat(bytes);
    const stream = new Blob([/** @type {Uint8Array<ArrayBuffer>} */ (bytes)])
      .stream()
      .pipeThrough(new DecompressionStream(format));
    const reader = stream.getReader();
    /** @type {Uint8Array[]} */
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        chunks.push(value);
        size += value.length;
        if (size > MAX_DECOMPRESSED) {
          await reader.cancel();
          break;
        }
      }
    } catch (err) {
      // (A truncated stream still gives what came before the error.)
      if (!size) {
        throw new Error(`Not ${format} data`, { cause: err });
      }
    }
    const out = new Uint8Array(Math.min(size, MAX_DECOMPRESSED));
    let at = 0;
    for (const c of chunks) {
      out.set(c.subarray(0, out.length - at), at);
      at += Math.min(c.length, out.length - at);
    }
    return { bytes: out, format, capped: size > MAX_DECOMPRESSED };
  }

  async function decode() {
    if (!state.field) {
      return;
    }
    const seq = ++state.seq;
    const raw = lib.hexToBytes(state.field.hex);
    let result;
    let note = "";
    if (state.decode === "compressed") {
      try {
        const out = await decompress(raw);
        result = { bytes: out.bytes, error: "" };
        note = ` · ${out.format} decompressed${out.capped ? ` (the first ${MAX_DECOMPRESSED / 1024 / 1024} MB)` : ""}`;
      } catch (err) {
        result = { bytes: raw, error: err instanceof Error ? err.message : String(err) };
      }
    } else {
      const out = lib.decodeBytes(raw, state.decode);
      result = { bytes: out.bytes, error: out.error || "" };
    }
    if (seq !== state.seq) {
      return; // (a newer field or decode came meanwhile)
    }
    state.decoded = result.error ? raw : result.bytes;
    state.error = result.error;
    state.decodeNote = note;
    state.start = Math.min(state.start, Math.max(0, state.decoded.length - 1));
    state.end = -1;
    startInput.value = String(state.start);
    endInput.value = String(Math.max(0, state.decoded.length - 1));
    startInput.max = endInput.max = String(Math.max(0, state.decoded.length - 1));
    renderBody();
  }

  /** The bytes from start to end. */
  function shown() {
    const end = state.end < 0 ? state.decoded.length - 1 : state.end;
    return state.decoded.subarray(state.start, end + 1);
  }

  /** What a text view shows (all of it: save and copy aren't limited by the render budget). */
  function shownText() {
    const view = state.view === "image" ? "hexdump" : state.view;
    return lib.bytesAs(shown(), view, state.field?.field || "packet_bytes");
  }

  function renderBody() {
    if (!state.field) {
      return;
    }
    const bytes = shown();
    notice.textContent = state.error ? `${state.error}: showing the bytes as they are.` : "";
    notice.classList.toggle("hidden", !state.error);
    const raw = state.field.hex.length / 2;
    const decoded = state.decode !== "none" && !state.error;
    status.textContent =
      `${bytes.length.toLocaleString()} of ${state.decoded.length.toLocaleString()} bytes` +
      (decoded ? ` (decoded from ${raw.toLocaleString()})` : "") +
      (decoded ? state.decodeNote : "");
    const image = state.view === "image";
    saveBtn.toggleAttribute("disabled", image);
    copyBtn.toggleAttribute("disabled", image);
    findInput.toggleAttribute("disabled", image);
    if (image) {
      const mime = lib.imageMime(bytes);
      state.matches = [];
      step(1);
      if (!mime) {
        body.replaceChildren(
          h("p", { class: "status" }, [
            "These bytes aren't an image PCAP Lens recognises (PNG, JPEG, GIF, WebP, BMP, ICO or SVG).",
          ]),
        );
        return;
      }
      const img = /** @type {HTMLImageElement} */ (
        h("img", { class: "bytes-image", alt: `Image from packet ${state.field.frame} (${mime})` })
      );
      img.src = `data:${mime};base64,${lib.bytesToBase64(bytes)}`;
      body.replaceChildren(img);
      return;
    }
    let text = shownText();
    const clipped = text.length > RENDER_BUDGET;
    if (clipped) {
      text = text.slice(0, RENDER_BUDGET);
      status.textContent += ` · showing the first ${RENDER_BUDGET.toLocaleString()} characters (save to get everything)`;
    }
    const pre = h("pre", { class: "bytes-text" });
    /** @type {HTMLElement[]} */
    const matches = [];
    let at = 0;
    for (const [start, end] of lib.findRanges(text, state.query, MAX_MATCHES)) {
      const mark = h("mark", { class: "find-match" });
      mark.textContent = text.slice(start, end);
      pre.append(text.slice(at, start), mark);
      matches.push(mark);
      at = end;
    }
    pre.append(text.slice(at));
    body.replaceChildren(pre);
    state.matches = matches;
    state.current = -1;
    step(1);
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
      findCount.textContent = state.query && state.view !== "image" ? "No matches" : "";
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
