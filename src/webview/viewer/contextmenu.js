// @ts-check
/** Context menus (packet list, detail tree) and their actions. */

import { el, lib, rpc, state, vscode } from "./core.js";
import { commandKeys, showMenu, viewerKeys } from "./menu.js";
import { visibleColumns } from "./columns.js";
import { rowAt } from "./list.js";
import { copyRows, focusIndex, selectAll, selectIndex, selectedFrames } from "./selection.js";
import { deleteComment, editComment, gotoFrame } from "./comments.js";
import { nodeIndex, selectNode, setExpanded } from "./detail.js";
import { applyFilter, validateSoon } from "./filterbar.js";
import { openFilterBuilder } from "./builder.js";
import {
  applyColumn,
  canBeColumn,
  copyFrameNumbers,
  frameLinkTarget,
  toggleIgnore,
  toggleMark,
  toggleTimeReference,
} from "./navigation.js";
/** @import { NodeEntry } from "./detail.js" */

/** @import { MenuEntry } from "./menu.js" */

/** @typedef {"tcp" | "udp" | "tls" | "http" | "http2" | "quic" | "websocket"} FollowKind */

/**
 * Shift+F10 and the menu key: Chromium turns them into "contextmenu" on
 * Windows and Linux but not on macOS, so the list and the tree handle the
 * keys themselves (a "contextmenu" without a pointer opens the selected row's
 * or node's menu) and ignore the "contextmenu" that may follow them.
 */
let keyMenuAt = -Infinity;
for (const pane of [el.viewport, el.tree]) {
  pane.addEventListener("keydown", (e) => {
    if ((e.key === "F10" && e.shiftKey) || e.key === "ContextMenu") {
      e.preventDefault();
      keyMenuAt = Date.now();
      pane.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
    }
  });
}

/** The browser's own "contextmenu" for a key just handled above. @param {MouseEvent} e */
function repeatedKeyMenu(e) {
  if (e.isTrusted && e.button !== 2 && Date.now() - keyMenuAt < 1000) {
    e.preventDefault();
    return true;
  }
  return false;
}

// The packet list's menu: right-click, Shift+F10 or the context menu key.
el.viewport.addEventListener("contextmenu", (e) => {
  if (repeatedKeyMenu(e)) {
    return;
  }
  const target = /** @type {HTMLElement} */ (e.target);
  let rowEl = /** @type {HTMLElement | null} */ (target.closest(".list-row"));
  let x = e.clientX;
  let y = e.clientY;
  // (From the keyboard the event comes to the focused grid, button 0: the selected row's menu.)
  if (!rowEl && e.button !== 2 && state.selectedIndex !== null) {
    rowEl = el.rows.querySelector(`.list-row[data-index="${state.selectedIndex}"]`);
    if (rowEl) {
      const rect = rowEl.getBoundingClientRect();
      x = rect.left + 24;
      y = rect.bottom;
    }
  }
  if (!rowEl || rowEl.dataset.index === undefined) {
    return;
  }
  e.preventDefault();
  const index = Number(rowEl.dataset.index);
  const row = rowAt(index);
  if (!row) {
    return; // (a row still loading: no menu, and the selection stays)
  }
  if (state.selection.has(row.number)) {
    focusIndex(index); // right-click inside a multi-selection keeps it
  } else if (state.selectedIndex !== index) {
    selectIndex(index);
  }
  // The clicked cell: Apply as Filter on its value (validated when applied).
  const cellEl = /** @type {HTMLElement | null} */ (target.closest(".list-row > div"));
  const vis = cellEl ? visibleColumns()[[...rowEl.children].indexOf(cellEl)] : undefined;
  // (A resolved name filters on its address.)
  const cellValue = vis ? (lib.cellAddress(vis.column, row) ?? row.cells[vis.index] ?? "") : "";
  const filter = vis ? lib.cellFilter(vis.column, cellValue) : null;
  showMenu(x, y, rowMenu(row, filter, cellValue));
});

/**
 * @param {any} row the clicked row @param {string | null} filter its cell's filter
 * @param {string} cellValue
 * @returns {MenuEntry[]}
 */
function rowMenu(row, filter, cellValue) {
  const multi = state.selection.size;
  const count = multi.toLocaleString();
  const frame = row.number;
  /** @type {MenuEntry[]} */
  const entries = [
    ...filterEntries(filter),
    {
      label: "Conversation Filter",
      icon: "arrow-swap",
      children: () => conversationItems(frame, (f) => applyFromTree(f, true)),
    },
    {
      label: "Colorize Conversation",
      icon: "symbol-color",
      children: () =>
        conversationItems(frame, (f) =>
          vscode.postMessage({ type: "colorizeConversation", filter: f }),
        ),
    },
  ];
  if (state.colorized) {
    entries.push({
      label: "Reset Colorization",
      icon: "discard",
      action: () => vscode.postMessage({ type: "runCommand", id: "pcapViewer.resetColorization" }),
    });
  }
  entries.push(
    "-",
    { label: "Follow", icon: "debug-step-over", children: () => followItems(row) },
    {
      label: multi === 2 ? "Compare 2 Selected Packets" : "Compare with Packet…",
      icon: "diff",
      action:
        multi > 2
          ? null
          : () =>
              vscode.postMessage({
                type: "compare",
                frames: multi === 2 ? selectedFrames().sort((a, b) => a - b) : [frame],
              }),
      title: multi > 2 ? "Select one or two packets to compare" : undefined,
    },
    {
      label: "Show Packet in New Window",
      icon: "multiple-windows",
      action: () => vscode.postMessage({ type: "packetWindow", frame }),
    },
  );
  // Sends packet data: the host asks for consent first (pcapViewer.ai.allowPacketData).
  if (state.ai.available) {
    entries.push({
      label: multi
        ? `Ask Copilot About ${count} Selected Packets…`
        : "Ask Copilot About This Packet…",
      icon: "sparkle",
      action: () =>
        vscode.postMessage({
          type: "askAboutPackets",
          frames: selectedFrames().sort((a, b) => a - b),
        }),
    });
  }
  entries.push(
    "-",
    {
      label: multi
        ? `Mark/Unmark ${count} Selected Packets`
        : row.marked
          ? "Unmark Packet"
          : "Mark Packet",
      icon: "bookmark",
      keys: commandKeys("pcapViewer.toggleMark"),
      action: () => void toggleMark(),
    },
    {
      label: multi
        ? `Ignore/Unignore ${count} Selected Packets`
        : row.ignored
          ? "Unignore Packet"
          : "Ignore Packet",
      icon: "eye-closed",
      keys: commandKeys("pcapViewer.toggleIgnore"),
      action: () => void toggleIgnore(),
    },
    {
      label: state.timeRef === frame ? "Unset Time Reference" : "Set Time Reference",
      icon: "clock",
      keys: commandKeys("pcapViewer.toggleTimeReference"),
      action: () => toggleTimeReference(),
    },
    {
      label: row.comment ? "Edit Packet Comment…" : "Add Packet Comment…",
      icon: "comment",
      keys: commandKeys("pcapViewer.editPacketComment"),
      action: () => editComment(),
    },
  );
  if (row.comment) {
    entries.push({
      label: "Delete Packet Comment",
      icon: "trash",
      action: () => deleteComment(frame),
    });
  }
  entries.push(
    "-",
    {
      label: "Decode As…",
      icon: "symbol-namespace",
      action: () => vscode.postMessage({ type: "decodeAs", frame }),
    },
    {
      label: "Export Packet Bytes…",
      icon: "file-binary",
      action: () => vscode.postMessage({ type: "exportBytes", frame }),
    },
  );
  if (multi) {
    entries.push({
      label: `Export ${count} Selected Packets…`,
      icon: "export",
      action: () => vscode.postMessage({ type: "exportSelected" }),
    });
  }
  /** @type {MenuEntry[]} */
  const copies = [];
  if (cellValue) {
    copies.push({ label: "Value", hint: cellValue, action: () => copy(cellValue) });
  }
  copies.push(
    multi
      ? { label: `${count} Rows`, keys: viewerKeys("ctrl+c"), action: () => void copyRows() }
      : {
          label: "Summary",
          keys: viewerKeys("ctrl+c"),
          action: () => copy(row.cells.join("\t")),
        },
    multi
      ? { label: `${count} Frame Numbers`, action: () => void copyFrameNumbers() }
      : { label: "Frame Number", hint: String(frame), action: () => copy(String(frame)) },
  );
  if (filter) {
    copies.push({ label: "As Filter", hint: filter, action: () => copy(filter) });
  }
  entries.push(
    "-",
    { label: "Copy", icon: "copy", children: copies },
    {
      label: "Select All",
      icon: "check-all",
      keys: viewerKeys("ctrl+a"),
      action: () => void selectAll(),
    },
  );
  return entries;
}

/**
 * Apply as Filter ▸ and Prepare as Filter ▸ for a field's filter (none when
 * the field has no filter).
 * @param {string | null} filter
 * @returns {MenuEntry[]}
 */
function filterEntries(filter) {
  if (!filter) {
    return [];
  }
  /** @param {boolean} apply @returns {MenuEntry[]} */
  const choices = (apply) =>
    lib.filterChoices(state.appliedFilter, filter).map(({ label, expr }) => ({
      label,
      hint: expr,
      title: expr,
      action: () => applyFromTree(expr, apply),
    }));
  return [
    {
      label: "Apply as Filter",
      icon: "filter",
      children: choices(true),
    },
    { label: "Prepare as Filter", icon: "edit", children: choices(false) },
  ];
}

/**
 * Packet `frame`'s exact detail: the one shown, else fetched. Stream numbers
 * need it (a quick view's are the window's), and the backend has it cached
 * when the packet is shown.
 * @param {number} frame
 */
async function exactDetail(frame) {
  if (state.detail?.number === frame && !state.detail.approximate) {
    return state.detail;
  }
  return rpc("packet_detail", { number: frame }).promise;
}

/**
 * The conversations of packet `frame` as menu items; picking one calls
 * `pick` with its filter.
 * @param {number} frame @param {(filter: string) => void} pick
 * @returns {Promise<MenuEntry[]>}
 */
async function conversationItems(frame, pick) {
  const detail = await exactDetail(frame);
  const conversations = detail ? lib.conversationFilters(detail.tree) : [];
  return conversations.length
    ? conversations.map(({ label, filter }) => ({
        label,
        hint: filter,
        title: filter,
        action: () => pick(filter),
      }))
    : [{ label: "No conversation for this packet", action: null }];
}

/**
 * Follow ▸: the streams the packet is part of (from its detail tree), then
 * its TCP stream graph.
 * @param {any} row
 * @returns {Promise<MenuEntry[]>}
 */
async function followItems(row) {
  const frame = row.number;
  /** @type {{label: string, proto: string}[]} */
  let streams;
  try {
    const detail = await exactDetail(frame);
    streams = lib.followOptions(detail?.tree ?? []);
  } catch {
    // (no detail: the transport protocols, as before)
    streams = [
      { label: "TCP Stream", proto: "tcp" },
      { label: "UDP Stream", proto: "udp" },
    ];
  }
  /** @type {MenuEntry[]} */
  const entries = streams.map(({ label, proto }) => ({
    label,
    action: () =>
      vscode.postMessage({ type: "follow", proto: /** @type {FollowKind} */ (proto), frame }),
  }));
  if (!entries.length) {
    entries.push({ label: "No stream to follow", action: null });
  }
  if (streams.some((s) => s.proto === "tcp")) {
    entries.push("-", {
      label: "TCP Stream Graph",
      icon: "graph-line",
      action: () => vscode.postMessage({ type: "tcpGraph", frame }),
    });
  }
  return entries;
}

// The detail tree's menu: right-click, Shift+F10 or the context menu key.
el.tree.addEventListener("contextmenu", (e) => {
  if (repeatedKeyMenu(e)) {
    return;
  }
  let row = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".node-row")
  );
  let x = e.clientX;
  let y = e.clientY;
  if (!row && e.button !== 2 && state.selectedNodeId !== null) {
    row = el.tree.querySelector(`.node-row[data-id="${state.selectedNodeId}"]`);
    if (row) {
      const rect = row.getBoundingClientRect();
      x = rect.left + 24;
      y = rect.bottom;
    }
  }
  const entry = row && nodeIndex.get(Number(row.dataset.id));
  if (!entry) {
    return;
  }
  e.preventDefault();
  selectNode(entry.node.id, { scroll: false });
  showTreeMenu(entry, x, y);
});

/**
 * The detail tree's menu for a field (also the packet diagram's, for its cells).
 * @param {NodeEntry} entry @param {number} x @param {number} y
 */
export function showTreeMenu(entry, x, y) {
  const node = entry.node;
  const filter = lib.buildFieldFilter(node);
  const prefsProtocol = lib.prefsProtocol(entry.path);
  const target = frameLinkTarget(node);
  const hasBytes = node.pos !== undefined && node.size > 0;
  /** @type {MenuEntry[]} */
  const entries = [...filterEntries(filter)];
  if (filter && !node.proto) {
    entries.push({
      label: "Build Filter from Field…",
      icon: "filter-filled",
      action: () =>
        openFilterBuilder({ field: node.name, value: node.show ?? "", returnTo: el.tree }),
    });
  }
  if (filter) {
    entries.push({
      label: "Colorize with Filter…",
      icon: "symbol-color",
      action: () => vscode.postMessage({ type: "colorize", filter }),
    });
  }
  if (canBeColumn(node)) {
    entries.push({
      label: "Apply as Column",
      icon: "split-horizontal",
      action: () => applyColumn(node),
    });
  }
  if (target !== null) {
    entries.push({
      label: `Go to Packet ${target}`,
      icon: "go-to-file",
      action: () => void gotoFrame(target),
    });
  }
  if (prefsProtocol) {
    entries.push("-", {
      label: `Protocol Preferences: ${prefsProtocol}…`,
      icon: "settings-gear",
      action: () => vscode.postMessage({ type: "protocolPrefs", protocol: prefsProtocol }),
    });
    if (prefsProtocol !== "frame") {
      entries.push({
        label: `Disable Protocol: ${prefsProtocol}`,
        icon: "circle-slash",
        action: () => vscode.postMessage({ type: "disableProtocol", protocol: prefsProtocol }),
      });
    }
  }
  /** @type {MenuEntry[]} */
  const copies = [];
  if (node.show !== undefined) {
    copies.push({ label: "Value", hint: node.show, action: () => copy(node.show) });
  }
  copies.push({ label: "Line", action: () => copy(node.label) });
  if (node.name) {
    copies.push({ label: "Field Name", hint: node.name, action: () => copy(node.name) });
  }
  if (filter) {
    copies.push({ label: "As Filter", hint: filter, action: () => copy(filter) });
  }
  if (node.pos !== undefined) {
    copies.push({ label: "Bytes (hex)", action: () => copy(fieldBytes(node)) });
  }
  entries.push("-", { label: "Copy", icon: "copy", children: copies });
  if (hasBytes && state.detail) {
    entries.push({
      label: "Show Packet Bytes…",
      icon: "file-binary",
      action: () =>
        vscode.postMessage({
          type: "showPacketBytes",
          frame: state.detail.number,
          field: node.name ?? "",
          label: node.label,
          hex: fieldBytes(node),
        }),
    });
  }
  if (entry.children) {
    entries.push(
      "-",
      { label: "Expand Subtrees", icon: "expand-all", action: () => expandAll(entry, true) },
      { label: "Collapse Subtrees", icon: "collapse-all", action: () => expandAll(entry, false) },
    );
  }
  showMenu(x, y, entries);
}

/** @param {any} node */
function fieldBytes(node) {
  const src = state.detail?.sources[node.src];
  return src ? src.hex.slice(node.pos * 2, (node.pos + node.size) * 2) : "";
}

/** @param {NodeEntry} entry @param {boolean} open */
function expandAll(entry, open) {
  setExpanded(entry, open);
  if (entry.built) {
    for (const child of entry.node.children) {
      const c = nodeIndex.get(child.id);
      if (c && c.children) {
        expandAll(c, open);
      }
    }
  }
}

/** @param {string} expr @param {boolean} apply */
function applyFromTree(expr, apply) {
  el.filterInput.value = expr;
  if (apply) {
    void applyFilter(expr);
  } else {
    el.filterInput.focus();
    validateSoon();
  }
}

/** @param {string} text */
export function copy(text) {
  vscode.postMessage({ type: "copy", text });
}
