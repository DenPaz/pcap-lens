// @ts-check
/** The packet detail tree, the hex view and the bytes pane's copy menu. */

import { CANCELLED, cancelRpc, el, lib, rpc, state, vscode } from "./core.js";
import { gotoFrame, showComment } from "./comments.js";
import { copy, showMenu } from "./contextmenu.js";
import { applyDetailView, clearDiagram, markDiagramSelection } from "./diagram.js";
import { decorateFrameLink, frameLinkTarget, loadFieldTypes } from "./navigation.js";
import { scheduleRender } from "./list.js";
import { persist } from "./status.js";

/** @param {number} frame */
/**
 * Show a packet's detail. The exact detail dissects the capture up to the
 * packet (cost grows with its number), so for late packets a quick view
 * (only pcapViewer.quickDetail.window packets dissected) is shown first,
 * marked approximate, until the exact one replaces it.
 * @param {number} frame
 */
export async function loadDetail(frame) {
  for (const id of [state.detailRequest, state.quickRequest]) {
    if (id !== null) {
      cancelRpc(id);
    }
  }
  state.quickRequest = null;
  if (state.detail && state.detail.number === frame && !state.detail.approximate) {
    return;
  }
  showDetailNote("", false); // the note belonged to the previous packet
  const q = state.quickDetail;
  // Small, complete captures: two passes, so references to later packets show too.
  const twoPass = !!q.twoPass && !state.indexing && !!state.info && state.info.frames <= q.twoPass;
  const req = rpc("packet_detail", { number: frame, ...(twoPass ? { twoPass } : {}) });
  state.detailRequest = req.id;
  let exactShown = false;
  el.treePlaceholder.textContent = `Loading packet ${frame}…`;
  el.treePlaceholder.classList.remove("hidden");
  if (q.after > 0 && frame > q.after && frame > q.window) {
    const quick = rpc("packet_detail", { number: frame, mode: "quick", window: q.window });
    state.quickRequest = quick.id;
    quick.promise.then(
      (detail) => {
        if (state.selectedFrame === frame && !exactShown && !detail.unavailable) {
          showDetail(detail);
        }
      },
      () => {
        /* the exact detail still comes */
      },
    );
  }
  try {
    const detail = await req.promise;
    exactShown = true;
    if (state.quickRequest !== null) {
      cancelRpc(state.quickRequest);
      state.quickRequest = null;
    }
    if (state.selectedFrame !== frame) {
      return;
    }
    showDetail(detail);
  } catch (err) {
    const e = /** @type {any} */ (err);
    if (e?.code !== CANCELLED && state.selectedFrame === frame) {
      if (state.detail?.number === frame && state.detail.approximate) {
        // Keep the quick view, but say the exact one failed.
        showDetailNote(
          `${quickNote(state.detail)} The exact view failed: ${e?.message ?? e}`,
          false,
        );
      } else {
        el.tree.replaceChildren();
        el.treePlaceholder.textContent = `Could not dissect packet ${frame}: ${e?.message ?? e}`;
      }
    }
  } finally {
    if (state.detailRequest === req.id) {
      state.detailRequest = null;
    }
  }
}

/** @param {any} detail a quick (approximate) detail */
function quickNote(detail) {
  const [first] = detail.window;
  return `Quick view: only packets ${first.toLocaleString()}–${detail.number.toLocaleString()} were dissected, so reassembly, TCP analysis and conversation details that depend on earlier packets can be missing.`;
}

/** @param {string} text @param {boolean} loading */
function showDetailNote(text, loading) {
  el.detailNote.textContent = text;
  el.detailNote.classList.toggle("loading", loading);
  el.detailNote.classList.toggle("hidden", !text);
}

/**
 * Tell the host which packet is selected (for "Follow Stream" etc.).
 * Tracked separately from state.selectedFrame, which selectIndex sets early.
 * @param {number | null} frame
 */
export function reportSelection(frame) {
  if (frame !== reportedFrame) {
    reportedFrame = frame;
    postSelection();
  }
}
/** @type {number | null} */
let reportedFrame = null;

/** The focused frame plus, for a multi-selection, every selected frame (Export Selected…). */
export function postSelection() {
  const frames = state.selection.size ? [...state.selection] : undefined;
  vscode.postMessage(
    frames
      ? { type: "selection", frame: reportedFrame, frames }
      : { type: "selection", frame: reportedFrame },
  );
}

export function clearDetail() {
  reportSelection(null);
  if (state.related.size) {
    state.related = new Map();
    scheduleRender();
  }
  void showComment(null);
  state.detail = null;
  state.selectedNodeId = null;
  nodeIndex.clear();
  showDetailNote("", false);
  el.tree.replaceChildren();
  el.treePlaceholder.textContent = "Select a packet to see its details.";
  el.treePlaceholder.classList.remove("hidden");
  el.bytesView.replaceChildren();
  el.bytesTabs.replaceChildren();
  el.bytesTabs.classList.add("hidden");
  hex = null;
  clearDiagram();
}

/**
 * @typedef {{node: any, path: any[], row: HTMLElement, children: HTMLElement | null, built: boolean}} NodeEntry
 * @type {Map<number, NodeEntry>}
 */
export const nodeIndex = new Map();

/** @param {any} detail */
function showDetail(detail) {
  const previous = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  const previousKey = previous ? lib.nodeKey(previous.path) : null;
  // The exact view replacing the quick one: keep the reader where they were.
  const sameFrame = state.detail?.number === detail.number;
  const scrollTop = el.detailPane.scrollTop;
  state.detail = detail;
  showDetailNote(
    detail.approximate ? `${quickNote(detail)} Loading the exact view` : "",
    !!detail.approximate,
  );
  state.selectedNodeId = null;
  nodeIndex.clear();
  el.treePlaceholder.classList.add("hidden");
  const frag = document.createDocumentFragment();
  for (const node of detail.tree) {
    frag.append(buildNode(node, [], 0));
  }
  el.tree.replaceChildren(frag);
  renderSourceTabs(detail.sources);
  hex = null;
  showSource(0);
  void loadFieldTypes(detail);
  // Keep the same field selected when moving between similar packets.
  if (previousKey) {
    for (const entry of nodeIndex.values()) {
      if (lib.nodeKey(entry.path) === previousKey) {
        selectNode(entry.node.id, { scroll: !sameFrame });
        break;
      }
    }
  }
  if (!revealFindMatch()) {
    applyDetailView(); // (draws the diagram when it is the view shown)
    if (sameFrame) {
      el.detailPane.scrollTop = scrollTop;
    }
  }
}

/**
 * Select the field a Find Packet search in the packet details matched, when
 * the details shown are the found packet's. Returns whether it did.
 */
export function revealFindMatch() {
  const match = state.findMatch;
  const detail = state.detail;
  if (!match || !detail || detail.number !== match.frame) {
    return false;
  }
  const path = lib.findTreeMatch(detail.tree, match);
  if (!path) {
    return false;
  }
  revealPath(path);
  applyDetailView();
  return true;
}

/**
 * @param {any} node @param {any[]} parentPath @param {number} depth
 * @returns {HTMLElement}
 */
function buildNode(node, parentPath, depth) {
  const path = [...parentPath, node];
  const wrap = document.createElement("div");
  wrap.setAttribute("role", "treeitem");
  const row = document.createElement("div");
  row.className =
    "node-row" +
    (node.proto ? " proto" : "") +
    (node.name && node.name.startsWith("_ws.expert") ? " expert" : "");
  row.dataset.id = String(node.id);
  // Indent and indent guides come from --depth (styles.css .node-row).
  row.style.setProperty("--depth", String(depth));
  const twisty = document.createElement("span");
  twisty.className = "twisty";
  twisty.setAttribute("aria-hidden", "true");
  const label = document.createElement("span");
  label.className = "label";
  label.textContent = node.label;
  row.append(twisty, label);
  wrap.append(row);
  /** @type {NodeEntry} */
  const entry = { node, path, row, children: null, built: false };
  nodeIndex.set(node.id, entry);
  decorateFrameLink(entry);
  if (node.children && node.children.length) {
    const children = document.createElement("div");
    children.setAttribute("role", "group");
    entry.children = children;
    wrap.append(children);
    const open = state.expanded.has(lib.nodeKey(path));
    setExpanded(entry, open, false);
  }
  return wrap;
}

/** @param {NodeEntry} entry @param {boolean} open @param {boolean} [remember] */
export function setExpanded(entry, open, remember = true) {
  if (!entry.children) {
    return;
  }
  if (open && !entry.built) {
    const depth = entry.path.length;
    const frag = document.createDocumentFragment();
    for (const child of entry.node.children) {
      frag.append(buildNode(child, entry.path, depth));
    }
    entry.children.append(frag);
    entry.built = true;
  }
  entry.children.classList.toggle("hidden", !open);
  const twisty = /** @type {HTMLElement} */ (entry.row.firstChild);
  twisty.className = `twisty codicon codicon-chevron-${open ? "down" : "right"}`;
  entry.row.setAttribute("aria-expanded", String(open));
  if (remember) {
    const key = lib.nodeKey(entry.path);
    if (open) {
      state.expanded.add(key);
    } else {
      state.expanded.delete(key);
    }
    persist();
  }
}

/** @param {NodeEntry} entry */
function isExpanded(entry) {
  return !!entry.children && !entry.children.classList.contains("hidden");
}

el.tree.addEventListener("click", (e) => {
  const row = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".node-row")
  );
  if (!row) {
    return;
  }
  const entry = nodeIndex.get(Number(row.dataset.id));
  if (!entry) {
    return;
  }
  if (/** @type {HTMLElement} */ (e.target).classList.contains("twisty")) {
    setExpanded(entry, !isExpanded(entry));
  }
  selectNode(entry.node.id, { scroll: false });
  const target = frameLinkTarget(entry.node);
  if (target !== null && /** @type {HTMLElement} */ (e.target).classList.contains("label")) {
    void gotoFrame(target);
  }
});

el.tree.addEventListener("dblclick", (e) => {
  const row = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".node-row")
  );
  const entry = row && nodeIndex.get(Number(row.dataset.id));
  if (entry) {
    setExpanded(entry, !isExpanded(entry));
  }
});

el.tree.addEventListener("keydown", (e) => {
  const visible = [...el.tree.querySelectorAll(".node-row")].filter(
    (r) => /** @type {HTMLElement} */ (r).offsetParent !== null,
  );
  if (!visible.length) {
    return;
  }
  const current = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  const idx = current ? visible.indexOf(current.row) : -1;
  /** @param {number} i */
  const go = (i) => {
    const row = /** @type {HTMLElement} */ (visible[Math.max(0, Math.min(visible.length - 1, i))]);
    selectNode(Number(row.dataset.id), { scroll: true });
  };
  switch (e.key) {
    case "ArrowDown":
      go(idx + 1);
      break;
    case "ArrowUp":
      go(idx - 1);
      break;
    case "Home":
      go(0);
      break;
    case "End":
      go(visible.length - 1);
      break;
    case "ArrowRight":
      if (current && current.children && !isExpanded(current)) {
        setExpanded(current, true);
      } else {
        go(idx + 1);
      }
      break;
    case "ArrowLeft":
      if (current && isExpanded(current)) {
        setExpanded(current, false);
      } else if (current && current.path.length > 1) {
        selectNode(current.path[current.path.length - 2].id, { scroll: true });
      } else {
        el.viewport.focus();
      }
      break;
    case "Enter": {
      const target = current ? frameLinkTarget(current.node) : null;
      if (target !== null) {
        void gotoFrame(target); // frame reference: follow it
      } else if (current) {
        setExpanded(current, !isExpanded(current));
      }
      break;
    }
    case " ":
      if (current) {
        setExpanded(current, !isExpanded(current));
      }
      break;
    default:
      return;
  }
  e.preventDefault();
});

/** @param {number} id @param {{scroll: boolean}} opts */
export function selectNode(id, opts) {
  const entry = nodeIndex.get(id);
  if (!entry) {
    return;
  }
  if (state.selectedNodeId !== null) {
    nodeIndex.get(state.selectedNodeId)?.row.classList.remove("selected");
  }
  state.selectedNodeId = id;
  entry.row.classList.add("selected");
  if (opts.scroll) {
    entry.row.scrollIntoView({ block: "nearest" });
  }
  highlightBytes(entry);
  markDiagramSelection();
}

/** Expand ancestors so a node deep in the tree becomes visible, then select it. @param {any[]} path */
export function revealPath(path) {
  for (let i = 0; i < path.length - 1; i++) {
    const entry = nodeIndex.get(path[i].id);
    if (entry && !isExpanded(entry)) {
      setExpanded(entry, true);
    }
  }
  selectNode(path[path.length - 1].id, { scroll: true });
}

/** @type {{src: number, bytes: HTMLElement[], ascii: HTMLElement[], marked: number[]} | null} */
let hex = null;

/** @param {{name: string, hex: string}[]} sources */
function renderSourceTabs(sources) {
  el.bytesTabs.replaceChildren();
  el.bytesTabs.classList.toggle("hidden", sources.length < 2);
  if (sources.length < 2) {
    return;
  }
  sources.forEach((s, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "tab");
    b.textContent = `${s.name} (${s.hex.length / 2})`;
    b.addEventListener("click", () => showSource(i));
    el.bytesTabs.append(b);
  });
}

/** @param {number} src */
function showSource(src) {
  const detail = state.detail;
  if (!detail || !detail.sources[src]) {
    el.bytesView.replaceChildren();
    hex = null;
    return;
  }
  if (hex && hex.src === src) {
    return;
  }
  state.activeSource = src;
  [...el.bytesTabs.children].forEach((b, i) => b.classList.toggle("active", i === src));
  const data = lib.hexToBytes(detail.sources[src].hex);
  /** @type {HTMLElement[]} */
  const byteEls = [];
  /** @type {HTMLElement[]} */
  const asciiEls = [];
  const frag = document.createDocumentFragment();
  for (let off = 0; off < data.length; off += 16) {
    const row = document.createElement("div");
    row.className = "hex-row";
    const offEl = document.createElement("span");
    offEl.className = "off";
    offEl.textContent = lib.formatOffset(off, data.length);
    row.append(offEl);
    const ascii = document.createElement("span");
    ascii.className = "ascii";
    for (let i = off; i < Math.min(off + 16, data.length); i++) {
      const b = document.createElement("span");
      b.className = "b" + (i - off === 7 ? " gap" : "");
      b.dataset.i = String(i);
      b.textContent = data[i].toString(16).padStart(2, "0");
      row.append(b);
      byteEls.push(b);
      const a = document.createElement("span");
      a.className = "a";
      a.dataset.i = String(i);
      a.textContent = lib.asciiChar(data[i]);
      ascii.append(a);
      asciiEls.push(a);
    }
    // Pad short final rows so the ASCII column lines up.
    for (let i = data.length; i < off + 16; i++) {
      const pad = document.createElement("span");
      pad.className = "b" + (i - off === 7 ? " gap" : "");
      pad.textContent = "  ";
      row.append(pad);
    }
    row.append(ascii);
    frag.append(row);
  }
  el.bytesView.replaceChildren(frag);
  hex = { src, bytes: byteEls, ascii: asciiEls, marked: [] };
  if (state.selectedNodeId !== null) {
    const entry = nodeIndex.get(state.selectedNodeId);
    if (entry) {
      highlightBytes(entry, false);
    }
  }
}

/** @param {NodeEntry} entry @param {boolean} [switchSource] follow the field to its byte source */
function highlightBytes(entry, switchSource = true) {
  const node = entry.node;
  if (switchSource && node.pos !== undefined && hex && node.src !== hex.src) {
    showSource(node.src); // re-renders, then highlights the selected node
    return;
  }
  if (!hex) {
    return;
  }
  for (const i of hex.marked) {
    hex.bytes[i]?.classList.remove("hl", "proto");
    hex.ascii[i]?.classList.remove("hl", "proto");
  }
  hex.marked = [];
  /** @param {any} n @param {string} cls */
  const mark = (n, cls) => {
    if (!hex || n.pos === undefined || n.src !== hex.src) {
      return;
    }
    const end = Math.min(n.pos + n.size, hex.bytes.length);
    for (let i = n.pos; i < end; i++) {
      hex.bytes[i].classList.add(cls);
      hex.ascii[i].classList.add(cls);
      hex.marked.push(i);
    }
  };
  // Lightly mark the enclosing protocol, strongly mark the field itself.
  if (entry.path.length > 1) {
    mark(entry.path[0], "proto");
  }
  mark(node, "hl");
  if (node.pos !== undefined && node.src === hex.src) {
    hex.bytes[Math.min(node.pos, hex.bytes.length - 1)]?.scrollIntoView({ block: "nearest" });
  }
}

el.bytesView.addEventListener("click", (e) => {
  const t = /** @type {HTMLElement} */ (e.target);
  if (t.dataset.i === undefined || !state.detail) {
    return;
  }
  const path = lib.findNodeForByte(state.detail.tree, state.activeSource, Number(t.dataset.i));
  if (path) {
    revealPath(path);
  }
});

/** @type {[string, "hexdump" | "hex" | "c" | "escaped" | "base64" | "text"][]} */
const BYTE_FORMATS = [
  ["Hex Dump", "hexdump"],
  ["Hex Stream", "hex"],
  ["C Array", "c"],
  ["Escaped String", "escaped"],
  ["Base64", "base64"],
  ["Printable Text", "text"],
];

el.bytesView.addEventListener("contextmenu", (e) => {
  if (!state.detail || !hex) {
    return;
  }
  e.preventDefault();
  const all = lib.hexToBytes(state.detail.sources[hex.src].hex);
  const entry = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  const node = entry?.node;
  const field =
    node && node.pos !== undefined && node.src === hex.src
      ? { bytes: all.subarray(node.pos, node.pos + node.size), offset: node.pos }
      : null;
  /** @type {[string, (() => void) | null][]} */
  const items = [
    ...BYTE_FORMATS.map(
      ([label, kind]) =>
        /** @type {[string, (() => void) | null]} */ ([
          `Copy Bytes as ${label}`,
          () => copy(lib.formatBytesAs(all, kind)),
        ]),
    ),
    ["-", null],
    ...BYTE_FORMATS.map(
      ([label, kind]) =>
        /** @type {[string, (() => void) | null]} */ ([
          `Copy Field Bytes as ${label}`,
          field ? () => copy(lib.formatBytesAs(field.bytes, kind, field.offset)) : null,
        ]),
    ),
  ];
  showMenu(e.clientX, e.clientY, items);
});
