// @ts-check
/** The packet detail tree, the hex view and the bytes pane's copy menu. */

import { CANCELLED, cancelRpc, el, isMac, lib, rpc, state, vscode } from "./core.js";
import { gotoFrame, showComment } from "./comments.js";
import { copy } from "./contextmenu.js";
import { showMenu } from "./menu.js";
import { applyDetailView, clearDiagram, markDiagramSelection } from "./diagram.js";
import { decorateFrameLink, frameLinkTarget, loadFieldTypes } from "./navigation.js";
import { scheduleRender } from "./list.js";
import { persist } from "./status.js";
import { showNotice } from "./filterbar.js";

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
  resetPending();
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
  showFieldStatus();
}

/** The selected field's name, filter field and size in the status bar ("" when none). */
export function showFieldStatus() {
  const node = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId)?.node : null;
  const text = node ? lib.fieldStatus(node, state.fieldTypes.get(node.name)?.desc) : "";
  el.statusField.textContent = text;
  el.statusField.title = text;
  el.statusField.classList.toggle("hidden", !text);
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
  // An Expand All still running on the quick view goes on in the exact one.
  const resumeExpandAll = sameFrame && expandingAll && !capped;
  state.detail = detail;
  showDetailNote(
    detail.approximate ? `${quickNote(detail)} Loading the exact view` : "",
    !!detail.approximate,
  );
  state.selectedNodeId = null;
  resetPending();
  nodeIndex.clear();
  el.treePlaceholder.classList.add("hidden");
  const frag = document.createDocumentFragment();
  for (const node of detail.tree) {
    frag.append(buildNode(node, [], 0));
  }
  el.tree.replaceChildren(frag);
  drainPending(); // (the nodes remembered open: at once, or in slices for a huge tree)
  renderSourceTabs(detail.sources);
  hex = null;
  showSource(0);
  void loadFieldTypes(detail);
  // Keep the same field selected when moving between similar packets (a
  // huge tree may build it in a later slice: selectWhenBuilt).
  if (previousKey && !selectKey(previousKey, !sameFrame) && pendingAt < pending.length) {
    selectWhenBuilt = { key: previousKey, scroll: !sameFrame };
  }
  if (resumeExpandAll) {
    expandAllNodes();
  }
  showFieldStatus(); // (the same field in this packet, or none)
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
 * A node's row (and, folded, the group its children go in). A node to be
 * open, remembered in state.expanded or under an Expand All (`all`), joins
 * the queue that drainPending opens: building a whole huge tree at once
 * froze the webview.
 * @param {any} node @param {any[]} parentPath @param {number} depth @param {boolean} [all]
 * @returns {HTMLElement}
 */
function buildNode(node, parentPath, depth, all = false) {
  rowsBuilt++;
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
    setExpanded(entry, false, false);
    if (all || state.expanded.has(lib.nodeKey(path))) {
      pending.push({ entry, all });
    }
  }
  return wrap;
}

/**
 * Open or fold one node (building its children's rows the first time).
 * `remember`: keep it in state.expanded for the next packets; `all`: its
 * children open too, all the way down (Expand All).
 * @param {NodeEntry} entry @param {boolean} open @param {boolean} [remember] @param {boolean} [all]
 */
export function setExpanded(entry, open, remember = true, all = false) {
  if (!entry.children) {
    return;
  }
  if (open && !entry.built) {
    const depth = entry.path.length;
    const frag = document.createDocumentFragment();
    for (const child of entry.node.children) {
      frag.append(buildNode(child, entry.path, depth, all));
    }
    entry.children.append(frag);
    entry.built = true;
  }
  entry.children.classList.toggle("hidden", !open);
  const twisty = /** @type {HTMLElement} */ (entry.row.firstChild);
  twisty.className = `twisty codicon codicon-chevron-${open ? "down" : "right"}`;
  // On the treeitem: the row itself has no role (axe: aria-allowed-attr).
  entry.row.parentElement?.setAttribute("aria-expanded", String(open));
  if (remember) {
    const key = lib.nodeKey(entry.path);
    if (open) {
      state.expanded.add(key);
    } else {
      state.expanded.delete(key);
    }
    persist();
  }
  if (open) {
    drainPending(); // (children remembered open)
  }
}

/** @param {NodeEntry} entry */
function isExpanded(entry) {
  return !!entry.children && !entry.children.classList.contains("hidden");
}

// ---------------------------------------------------- opening many nodes

/** Nodes to open, in the order found (breadth first), from pendingAt on. */
/** @type {{entry: NodeEntry, all: boolean}[]} */
let pending = [];
let pendingAt = 0;
let draining = false;
let drainTimer = 0;
/** Rows buildNode built in the current slice. */
let rowsBuilt = 0;
/** An Expand All is running; the rows it built; whether it hit lib.TREE_EXPAND_MAX. */
let expandingAll = false;
let expandedRows = 0;
let capped = false;
/** @type {{key: string, scroll: boolean} | null} */
let selectWhenBuilt = null;

function resetPending() {
  window.clearTimeout(drainTimer);
  pending = [];
  pendingAt = 0;
  expandingAll = false;
  capped = false;
  selectWhenBuilt = null;
}

/**
 * Open the queued nodes, lib.TREE_EXPAND_SLICE rows at a time: the first
 * slice now (a normal tree opens at once), the rest after yielding to the
 * browser, so expanding a tree of a hundred thousand fields doesn't freeze
 * the webview. An Expand All stops at lib.TREE_EXPAND_MAX rows.
 */
function drainPending() {
  if (draining) {
    return; // (setExpanded calls it back while a slice runs)
  }
  draining = true;
  window.clearTimeout(drainTimer);
  rowsBuilt = 0;
  try {
    while (pendingAt < pending.length && rowsBuilt < lib.TREE_EXPAND_SLICE) {
      const { entry, all } = pending[pendingAt++];
      const key = lib.nodeKey(entry.path);
      if (all) {
        if (expandedRows >= lib.TREE_EXPAND_MAX) {
          capped = true;
          continue;
        }
        state.expanded.add(key);
      } else if (!state.expanded.has(key)) {
        continue; // (folded meanwhile)
      }
      const before = rowsBuilt;
      const built = entry.built;
      setExpanded(entry, true, false, all);
      if (all) {
        expandedRows += rowsBuilt - before;
        if (built) {
          // (Its children were built earlier: queue the ones that have children.)
          for (const child of entry.node.children) {
            const c = nodeIndex.get(child.id);
            if (c?.children) {
              pending.push({ entry: c, all: true });
            }
          }
        }
      }
    }
  } finally {
    draining = false;
  }
  if (selectWhenBuilt && selectKey(selectWhenBuilt.key, selectWhenBuilt.scroll)) {
    selectWhenBuilt = null;
  }
  if (pendingAt < pending.length) {
    drainTimer = window.setTimeout(drainPending, 0);
    return;
  }
  pending = [];
  pendingAt = 0;
  selectWhenBuilt = null;
  if (expandingAll) {
    expandingAll = false;
    persist();
    revealSelected();
    if (capped) {
      showNotice(
        `Expanded the first ${lib.TREE_EXPAND_MAX.toLocaleString()} fields of this packet; ` +
          "the rest stay folded.",
      );
    }
  }
}

/** Select the first node whose nodeKey is `key`; whether there was one. @param {string} key @param {boolean} scroll */
function selectKey(key, scroll) {
  for (const entry of nodeIndex.values()) {
    if (lib.nodeKey(entry.path) === key) {
      selectNode(entry.node.id, { scroll });
      return true;
    }
  }
  return false;
}

/** Scroll the selected node into view (after opening or folding around it). */
function revealSelected() {
  const entry = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  entry?.row.scrollIntoView({ block: "nearest" });
}

/** The top-level protocols' entries of the packet shown. */
function topEntries() {
  return /** @type {NodeEntry[]} */ (
    (state.detail?.tree ?? []).map((/** @type {any} */ n) => nodeIndex.get(n.id)).filter(Boolean)
  );
}

/**
 * Open `entries` and everything under them (Expand Subtrees, Shift+→), in
 * slices; each node is remembered open, as a click on it would.
 * @param {NodeEntry[]} entries
 */
export function expandSubtrees(entries) {
  if (!expandingAll) {
    expandedRows = 0;
    capped = false;
  }
  expandingAll = true;
  for (const entry of entries) {
    if (entry.children) {
      pending.push({ entry, all: true });
    }
  }
  drainPending();
  revealSelected();
}

/**
 * Fold `entries` and everything under them, and forget them in
 * state.expanded (Collapse Subtrees). A selected node they hide hands the
 * selection to the folded node above it.
 * @param {NodeEntry[]} entries
 */
export function collapseSubtrees(entries) {
  const roots = entries.filter((e) => e.children);
  const rootNodes = new Set(roots.map((e) => e.node));
  /** @param {NodeEntry} e */
  const under = (e) => e.path.some((n) => rootNodes.has(n));
  pending = pending.slice(pendingAt).filter((p) => !under(p.entry)); // (no more opening there)
  pendingAt = 0;
  for (const root of roots) {
    for (const key of lib.subtreeKeys(root.path)) {
      state.expanded.delete(key);
    }
  }
  for (const entry of nodeIndex.values()) {
    if (entry.children && under(entry) && isExpanded(entry)) {
      setExpanded(entry, false, false);
    }
  }
  persist();
  const selected = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  if (selected && under(selected) && !rootNodes.has(selected.node)) {
    const holder = selected.path.find((n) => rootNodes.has(n));
    selectNode(holder.id, { scroll: true });
  } else {
    revealSelected();
  }
}

/** Expand All: every node of the packet shown. */
export function expandAllNodes() {
  expandSubtrees(topEntries());
}

/** Collapse All: every node folded; a hidden selection moves to its top-level protocol. */
export function collapseAllNodes() {
  collapseSubtrees(topEntries());
}

/** The keys of Expand All and Collapse All (⌘ on macOS, where Ctrl+arrows switch desktops). */
export const TREE_KEYS = {
  expandAll: { key: "ctrl+right", mac: "cmd+right" },
  collapseAll: { key: "ctrl+left", mac: "cmd+left" },
  expandSubtree: { key: "shift+right" },
};

/** @param {keyof typeof TREE_KEYS} name */
export function treeKeyLabel(name) {
  return lib.formatKeybinding(TREE_KEYS[name], isMac);
}

el.treeExpandAll.title = `Expand All (${treeKeyLabel("expandAll")})`;
el.treeCollapseAll.title = `Collapse All (${treeKeyLabel("collapseAll")})`;
el.treeExpandAll.addEventListener("click", () => expandAllNodes());
el.treeCollapseAll.addEventListener("click", () => collapseAllNodes());

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
  // As in Wireshark: Ctrl+→ / Ctrl+← (⌘ on macOS) expand and collapse every
  // node, Shift+→ the selected node's whole subtree. (Checked before the
  // plain arrows below, which ignore modifiers.)
  if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      if (e.key === "ArrowRight") {
        expandAllNodes();
      } else {
        collapseAllNodes();
      }
      return;
    }
  }
  if (e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey && e.key === "ArrowRight") {
    e.preventDefault();
    if (current) {
      expandSubtrees([current]);
    }
    return;
  }
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
  showFieldStatus();
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
  /** @type {import("./menu.js").MenuEntry[]} */
  const items = [
    {
      label: "Copy Bytes as",
      icon: "copy",
      children: BYTE_FORMATS.map(([label, kind]) => ({
        label,
        action: () => copy(lib.formatBytesAs(all, kind)),
      })),
    },
  ];
  if (field) {
    items.push({
      label: "Copy Field Bytes as",
      icon: "symbol-field",
      children: BYTE_FORMATS.map(([label, kind]) => ({
        label,
        action: () => copy(lib.formatBytesAs(field.bytes, kind, field.offset)),
      })),
    });
  }
  showMenu(e.clientX, e.clientY, items);
});
