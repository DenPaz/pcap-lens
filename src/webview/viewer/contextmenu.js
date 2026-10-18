// @ts-check
/** Context menus (packet list, detail tree) and their actions. */

import { el, icon, lib, rpc, state, vscode } from "./core.js";
import { visibleColumns } from "./columns.js";
import { rowAt } from "./list.js";
import { copyRows, focusIndex, selectAll, selectIndex, selectedFrames } from "./selection.js";
import { deleteComment, editComment, gotoFrame } from "./comments.js";
import { nodeIndex, selectNode, setExpanded } from "./detail.js";
import { applyFilter, validateSoon } from "./filterbar.js";
import {
  applyColumn,
  canBeColumn,
  copyFrameNumbers,
  frameLinkTarget,
  toggleMark,
  toggleTimeReference,
} from "./navigation.js";
/** @import { NodeEntry } from "./detail.js" */

// Packet list: follow the selected packet's stream.
el.rows.addEventListener("contextmenu", (e) => {
  const rowEl = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".list-row")
  );
  if (!rowEl || rowEl.dataset.index === undefined) {
    return;
  }
  e.preventDefault();
  const index = Number(rowEl.dataset.index);
  const row = rowAt(index);
  if (row && state.selection.has(row.number)) {
    focusIndex(index); // right-click inside a multi-selection keeps it
  } else {
    selectIndex(index);
  }
  if (!row) {
    return;
  }
  const multi = state.selection.size;
  const protocol = (row.cells[4] || "").toUpperCase();
  /** @param {"tcp" | "udp" | "tls" | "http"} proto */
  const follow = (proto) => () => vscode.postMessage({ type: "follow", proto, frame: row.number });
  // The clicked cell: Apply as Filter on its value (validated when applied).
  const cellEl = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".list-row > div")
  );
  const vis = cellEl ? visibleColumns()[[...rowEl.children].indexOf(cellEl)] : undefined;
  // (A resolved name filters on its address.)
  const cellValue = vis ? (lib.cellAddress(vis.column, row) ?? row.cells[vis.index] ?? "") : "";
  const filter = vis ? lib.cellFilter(vis.column, cellValue) : null;
  const current = state.appliedFilter;
  /** @type {[string, (() => void) | null][]} */
  const items = [
    [
      "Apply as Filter",
      filter ? () => applyFromTree(lib.combineFilter(current, filter, "replace"), true) : null,
    ],
    ["Prepare as Filter", filter ? () => applyFromTree(filter, false) : null],
    [
      "…and Selected",
      filter && current
        ? () => applyFromTree(lib.combineFilter(current, filter, "and"), true)
        : null,
    ],
    [
      "…or Selected",
      filter && current
        ? () => applyFromTree(lib.combineFilter(current, filter, "or"), true)
        : null,
    ],
    [
      "…and not Selected",
      filter ? () => applyFromTree(lib.combineFilter(current, filter, "not"), true) : null,
    ],
    // A second menu at the same spot: the packet's Ethernet/IP/TCP/UDP conversations.
    [
      "Conversation Filter…",
      () => void conversationMenu(row.number, e.clientX, e.clientY, (f) => applyFromTree(f, true)),
    ],
    [
      "Colorize Conversation…",
      () =>
        void conversationMenu(row.number, e.clientX, e.clientY, (f) =>
          vscode.postMessage({ type: "colorizeConversation", filter: f }),
        ),
    ],
    [
      "Reset Colorization",
      state.colorized
        ? () => vscode.postMessage({ type: "runCommand", id: "pcapViewer.resetColorization" })
        : null,
    ],
    ["-", null],
    ["Follow TCP Stream", follow("tcp")],
    ["Follow UDP Stream", follow("udp")],
    ["Follow TLS Stream", /TLS|SSL/.test(protocol) ? follow("tls") : null],
    ["Follow HTTP Stream", /HTTP/.test(protocol) ? follow("http") : null],
    ["TCP Stream Graph", () => vscode.postMessage({ type: "tcpGraph", frame: row.number })],
    ["-", null],
    // Sends packet data: the host asks for consent first (pcapViewer.ai.allowPacketData).
    ...(state.ai.available
      ? /** @type {[string, (() => void) | null][]} */ ([
          [
            multi
              ? `Ask Copilot About ${multi.toLocaleString()} Selected Packets…`
              : "Ask Copilot About This Packet…",
            () =>
              vscode.postMessage({
                type: "askAboutPackets",
                frames: selectedFrames().sort((a, b) => a - b),
              }),
          ],
          ["-", null],
        ])
      : []),
    ["Decode As…", () => vscode.postMessage({ type: "decodeAs", frame: row.number })],
    ["Export Packet Bytes…", () => vscode.postMessage({ type: "exportBytes", frame: row.number })],
    ["-", null],
    [
      multi
        ? `Mark/Unmark ${multi.toLocaleString()} Selected Packets`
        : row.marked
          ? "Unmark Packet"
          : "Mark Packet",
      () => void toggleMark(),
    ],
    [
      state.timeRef === row.number ? "Unset Time Reference" : "Set Time Reference",
      () => toggleTimeReference(),
    ],
    [row.comment ? "Edit Packet Comment…" : "Add Packet Comment…", () => editComment()],
    ["Delete Packet Comment", row.comment ? () => deleteComment(row.number) : null],
    ["Select All", () => void selectAll()],
    ["-", null],
    ["Copy Value", cellValue ? () => copy(cellValue) : null],
    ...(multi
      ? /** @type {[string, (() => void) | null][]} */ ([
          [`Copy ${multi.toLocaleString()} Rows`, () => void copyRows()],
          [`Copy ${multi.toLocaleString()} Frame Numbers`, () => void copyFrameNumbers()],
          [
            `Export ${multi.toLocaleString()} Selected Packets…`,
            () => vscode.postMessage({ type: "exportSelected" }),
          ],
        ])
      : /** @type {[string, (() => void) | null][]} */ ([
          ["Copy Summary", () => copy(row.cells.join("\t"))],
          ["Copy Frame Number", () => copy(String(row.number))],
        ])),
  ];
  showMenu(e.clientX, e.clientY, items);
});

/**
 * The conversations of packet `frame` as a menu; picking one calls `pick`
 * with its filter. Stream numbers need the exact detail (a quick view's are
 * the window's), which the backend has cached when the packet is shown.
 * @param {number} frame @param {number} x @param {number} y
 * @param {(filter: string) => void} pick
 */
async function conversationMenu(frame, x, y, pick) {
  let detail = state.detail?.number === frame && !state.detail.approximate ? state.detail : null;
  if (!detail) {
    showMenu(x, y, [[`Reading packet ${frame}…`, null]]);
    try {
      detail = await rpc("packet_detail", { number: frame }).promise;
    } catch {
      detail = null;
    }
    if (el.menu.classList.contains("hidden")) {
      return; // closed meanwhile
    }
  }
  const conversations = detail ? lib.conversationFilters(detail.tree) : [];
  showMenu(
    x,
    y,
    conversations.length
      ? conversations.map(({ label, filter }) => [label, () => pick(filter)])
      : [["No conversation for this packet", null]],
  );
}

el.tree.addEventListener("contextmenu", (e) => {
  const row = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".node-row")
  );
  const entry = row && nodeIndex.get(Number(row.dataset.id));
  if (!entry) {
    return;
  }
  e.preventDefault();
  selectNode(entry.node.id, { scroll: false });
  showTreeMenu(entry, e.clientX, e.clientY);
});

/**
 * The detail tree's menu for a field (also the packet diagram's, for its cells).
 * @param {NodeEntry} entry @param {number} x @param {number} y
 */
export function showTreeMenu(entry, x, y) {
  const node = entry.node;
  const filter = lib.buildFieldFilter(node);
  const prefsProtocol = lib.prefsProtocol(entry.path);
  const current = state.appliedFilter;
  /** @type {[string, (() => void) | null][]} */
  const items = [
    [
      "Apply as Filter",
      filter ? () => applyFromTree(lib.combineFilter(current, filter, "replace"), true) : null,
    ],
    ["Prepare as Filter", filter ? () => applyFromTree(filter, false) : null],
    [
      "…and Selected",
      filter && current
        ? () => applyFromTree(lib.combineFilter(current, filter, "and"), true)
        : null,
    ],
    [
      "…or Selected",
      filter && current
        ? () => applyFromTree(lib.combineFilter(current, filter, "or"), true)
        : null,
    ],
    [
      "…and not Selected",
      filter ? () => applyFromTree(lib.combineFilter(current, filter, "not"), true) : null,
    ],
    [
      "Colorize with Filter…",
      filter ? () => vscode.postMessage({ type: "colorize", filter }) : null,
    ],
    ["Apply as Column", canBeColumn(node) ? () => applyColumn(node) : null],
    prefsProtocol
      ? [
          `Protocol Preferences: ${prefsProtocol}…`,
          () => vscode.postMessage({ type: "protocolPrefs", protocol: prefsProtocol }),
        ]
      : ["Protocol Preferences…", null],
    ...(frameLinkTarget(node) !== null
      ? /** @type {[string, (() => void) | null][]} */ ([
          [
            `Go to Packet ${frameLinkTarget(node)}`,
            () => void gotoFrame(/** @type {number} */ (frameLinkTarget(node))),
          ],
        ])
      : []),
    ["-", null],
    ["Copy Value", node.show !== undefined ? () => copy(node.show) : null],
    ["Copy Line", () => copy(node.label)],
    ["Copy Field Name", node.name ? () => copy(node.name) : null],
    ["Copy as Filter", filter ? () => copy(filter) : null],
    ["Copy Bytes (hex)", node.pos !== undefined ? () => copy(fieldBytes(node)) : null],
    ["-", null],
    ["Expand Subtrees", entry.children ? () => expandAll(entry, true) : null],
    ["Collapse Subtrees", entry.children ? () => expandAll(entry, false) : null],
  ];
  showMenu(x, y, items);
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

/**
 * Items are [label, action (null = disabled), checked]; "-" is a separator.
 * A boolean `checked` makes a checkbox item with a check mark.
 * @param {number} x @param {number} y @param {[string, (() => void) | null, boolean?][]} items
 */
export function showMenu(x, y, items) {
  el.menu.replaceChildren(
    ...items.map(([label, action, checked]) => {
      const item = document.createElement("div");
      if (label === "-") {
        item.className = "sep";
        return item;
      }
      item.className = "item" + (action ? "" : " disabled");
      item.setAttribute("role", "menuitem");
      item.tabIndex = -1;
      item.textContent = label;
      if (checked !== undefined) {
        item.setAttribute("role", "menuitemcheckbox");
        item.setAttribute("aria-checked", String(checked));
        item.classList.add("checkable");
        item.prepend(icon(checked ? "check" : "blank"));
      }
      if (action) {
        item.addEventListener("click", () => {
          hideMenu();
          action();
        });
      }
      return item;
    }),
  );
  el.menu.classList.remove("hidden");
  const rect = el.menu.getBoundingClientRect();
  el.menu.style.left = `${Math.min(x, window.innerWidth - rect.width - 4)}px`;
  el.menu.style.top = `${Math.min(y, window.innerHeight - rect.height - 4)}px`;
}

export function hideMenu() {
  el.menu.classList.add("hidden");
}

window.addEventListener("mousedown", (e) => {
  if (!el.menu.contains(/** @type {Node} */ (e.target))) {
    hideMenu();
  }
});
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    hideMenu();
  }
});
window.addEventListener("blur", hideMenu);
