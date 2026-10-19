// @ts-check
/**
 * Navigation (history, frame links, Find Packet, conversations, marks, time
 * reference), Apply as Column, and the keyboard commands the host sends.
 */

import { CANCELLED, cancelRpc, el, lib, rpc, state, vscode } from "./core.js";
import { orderParams, refreshRows, scheduleRender } from "./list.js";
import { selectAll, selectIndex, selectedFrames } from "./selection.js";
import { deleteComment, editComment, gotoFrame } from "./comments.js";
import { nodeIndex, revealFindMatch, showFieldStatus } from "./detail.js";
import { copy } from "./contextmenu.js";
import { showNotice } from "./filterbar.js";
import { loadExpertSummary, updateStatus } from "./status.js";
import { openShortcuts } from "./shortcuts.js";
import { openFilterBuilder } from "./builder.js";
/** @import { NodeEntry } from "./detail.js" */

const MAX_HISTORY = 100;

/** Remember where a jump starts (Alt+Left comes back here). @param {number} [target] */
export function recordJump(target) {
  const from = state.selectedFrame;
  if (from !== null && from !== target) {
    state.nav.back.push(from);
    if (state.nav.back.length > MAX_HISTORY) {
      state.nav.back.shift();
    }
    state.nav.forward = [];
  }
}

/** Select a row found by the backend (find, marks, conversation, first/last). */
function jumpToIndex(
  /** @type {number} */ index,
  /** @type {number | null} */ frame,
  /** @type {boolean} */ focusList,
) {
  recordJump(frame ?? undefined);
  selectIndex(index, true);
  if (focusList) {
    el.viewport.focus();
  }
}

/** @param {"back" | "forward"} which */
async function goHistory(which) {
  const from = which === "back" ? state.nav.back : state.nav.forward;
  const to = which === "back" ? state.nav.forward : state.nav.back;
  const frame = from.pop();
  if (frame === undefined) {
    showNotice(
      which === "back" ? "No earlier packet to go back to." : "No later packet to go forward to.",
    );
    return;
  }
  if (state.selectedFrame !== null) {
    to.push(state.selectedFrame);
  }
  await gotoFrame(frame, { record: false });
}

/** Frame number a detail-tree node links to (FT_FRAMENUM fields such as tcp.analysis.acks_frame). @param {any} node */
export function frameLinkTarget(node) {
  const type = node.name ? state.fieldTypes.get(node.name)?.type : undefined;
  if (type !== "FT_FRAMENUM") {
    return null;
  }
  const n = Number(node.show);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** @param {NodeEntry} entry */
export function decorateFrameLink(entry) {
  const target = frameLinkTarget(entry.node);
  if (target !== null && !entry.row.classList.contains("frame-link")) {
    entry.row.classList.add("frame-link");
    entry.row.title = `Go to packet ${target} (click or Enter; Alt+Left comes back)`;
  }
}

/** Look up the types of the packet's fields (once per name), then mark frame links. @param {any} detail */
export async function loadFieldTypes(detail) {
  /** @type {Set<string>} */
  const names = new Set();
  /** @param {any[]} nodes */
  const walk = (nodes) => {
    for (const n of nodes) {
      if (n.name && !state.fieldTypes.has(n.name)) {
        names.add(n.name);
      }
      if (n.children) {
        walk(n.children);
      }
    }
  };
  walk(detail.tree);
  if (names.size) {
    try {
      const res = await rpc("field_types", { names: [...names].slice(0, 2000) }).promise;
      for (const name of names) {
        state.fieldTypes.set(name, res.types[name] ?? { type: "", desc: "" });
      }
    } catch {
      return;
    }
  }
  if (state.detail === detail) {
    for (const entry of nodeIndex.values()) {
      decorateFrameLink(entry);
    }
    showFieldStatus(); // (the selected field's display name has arrived)
    // The packets it refers to get a mark in the list.
    state.related = lib.relatedFrames(
      detail.tree,
      (name) => state.fieldTypes.get(name)?.type,
      detail.number,
    );
    scheduleRender();
  }
}

/** @param {any} node */
export function canBeColumn(node) {
  return (
    !!node.name &&
    !node.proto &&
    node.name !== "fake-field-wrapper" &&
    /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(node.name)
  );
}

/** "Apply as Column": the host adds it to pcapViewer.columns (capture's folder scope). @param {any} node */
export function applyColumn(node) {
  const desc = state.fieldTypes.get(node.name)?.desc;
  const title = desc || String(node.label).split(":")[0].trim() || node.name;
  vscode.postMessage({ type: "applyColumn", field: node.name, title });
}

/** @type {Record<string, string>} */
const FIND_PLACEHOLDERS = {
  filter: "Display filter, e.g. dns.flags.rcode != 0 (Enter: next, Shift+Enter: previous)",
  "string bytes": "Text in the packet bytes, e.g. index.html",
  "string list": "Text in the packet list's columns, e.g. Retransmission",
  "string details": "Text in the packet details, e.g. Server: nginx",
  "regex bytes": "Regular expression on the packet bytes, e.g. GET /\\w+\\.php",
  "regex list": "Regular expression on the packet list's columns, e.g. ^GET .*\\.php",
  "regex details": "Regular expression on the packet details, e.g. ^Time to Live: 1$",
  hex: "Hex bytes, e.g. 47 45 54 or 47:45:54",
};

/** Whether the find mode searches text, which can be in the bytes, list or details. */
const textMode = () => el.findMode.value === "string" || el.findMode.value === "regex";
/** @type {number | null} */
let findRequest = null;

function openFind() {
  el.findBar.classList.remove("hidden");
  updateFindMode();
  el.findInput.focus();
  el.findInput.select();
}

function closeFind() {
  el.findBar.classList.add("hidden");
  scheduleRender(); // (the overview stops showing the matches)
  state.findMatch = null;
  setFindStatus("");
  el.viewport.focus();
}

function updateFindMode() {
  const text = textMode();
  el.findInput.placeholder =
    FIND_PLACEHOLDERS[text ? `${el.findMode.value} ${el.findIn.value}` : el.findMode.value] ?? "";
  el.findIn.classList.toggle("hidden", !text);
  el.findCaseLabel.classList.toggle("hidden", !text);
  checkFindInput();
}

/** Immediate feedback for hex input (the backend validates everything again). */
function checkFindInput() {
  const bad =
    el.findMode.value === "hex" &&
    el.findInput.value.trim() !== "" &&
    !lib.parseHexBytes(el.findInput.value);
  el.findInput.classList.toggle("invalid", bad);
  if (bad) {
    setFindStatus("Not hex bytes", true);
  } else if (el.findStatus.classList.contains("error")) {
    setFindStatus("");
  }
  return !bad;
}

/** @param {string} text @param {boolean} [error] */
function setFindStatus(text, error = false) {
  el.findStatus.textContent = text;
  el.findStatus.title = text;
  el.findStatus.classList.toggle("error", error);
}

/** Next/previous match in the current view (filter and sort order), wrapping around. @param {"next" | "previous"} direction */
async function find(direction) {
  if (!state.ready) {
    return;
  }
  if (el.findBar.classList.contains("hidden") || !el.findInput.value.trim()) {
    openFind();
    return;
  }
  if (!checkFindInput()) {
    return;
  }
  if (findRequest !== null) {
    cancelRpc(findRequest);
  }
  const where = textMode() ? el.findIn.value : "bytes";
  const search = {
    value: el.findInput.value,
    regex: el.findMode.value === "regex",
    caseSensitive: el.findCase.checked,
  };
  state.findVersion++; // (the backend replaces its matches with this search's)
  const req = rpc("find_packet", {
    mode: el.findMode.value,
    value: search.value,
    caseSensitive: search.caseSensitive,
    in: where,
    // (The packet list search covers the custom columns shown.)
    columns: state.customColumns.map((c) => c.field),
    from: state.selectedFrame,
    direction,
    ...orderParams(),
  });
  findRequest = req.id;
  setFindStatus("Searching…");
  try {
    const res = await req.promise;
    if (res.filterId !== state.filterId) {
      return;
    }
    if (res.frame === null || res.frame === undefined) {
      setFindStatus("Not found", true);
      return;
    }
    setFindStatus(res.wrapped ? `Packet ${res.frame} (wrapped around)` : `Packet ${res.frame}`);
    state.findMatch = where === "details" ? { frame: res.frame, ...search } : null;
    jumpToIndex(res.index, res.frame, false);
    revealFindMatch(); // (when that packet's details are already shown; else once they are)
  } catch (err) {
    const e = /** @type {any} */ (err);
    if (e?.code !== CANCELLED) {
      setFindStatus(String(e?.message ?? e), true);
    }
  } finally {
    if (findRequest === req.id) {
      findRequest = null;
    }
  }
}

el.findMode.addEventListener("change", () => {
  updateFindMode();
  el.findInput.focus();
});
el.findIn.addEventListener("change", () => {
  updateFindMode();
  el.findInput.focus();
});
el.findInput.addEventListener("input", checkFindInput);
el.findInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    void find(e.shiftKey ? "previous" : "next");
  } else if (e.key === "Escape") {
    e.preventDefault();
    closeFind();
  }
});
el.findNext.addEventListener("click", () => void find("next"));
el.findPrev.addEventListener("click", () => void find("previous"));
el.findClose.addEventListener("click", closeFind);

/** @param {"next" | "previous"} direction */
async function stepConversation(direction) {
  const frame = state.selectedFrame;
  if (frame === null) {
    showNotice("Select a packet first.");
    return;
  }
  try {
    const res = await rpc("neighbor_frame", { frame, direction, ...orderParams() }).promise;
    if (res.frame === null || res.frame === undefined) {
      showNotice(
        `No ${direction} packet in this conversation${state.appliedFilter ? " among the displayed packets" : ""}.`,
      );
      return;
    }
    jumpToIndex(res.index, res.frame, true);
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

/** Patch cached rows instead of refetching. @param {number[]} marked @param {number[]} unmarked */
function patchMarks(marked, unmarked) {
  patchRows("marked", marked, unmarked);
}

/**
 * Set or clear a row flag in the cached pages (instead of refetching them).
 * @param {"marked" | "ignored"} flag @param {number[]} on @param {number[] | null} off null: every row
 */
function patchRows(flag, on, off) {
  const set = new Set(on);
  const clear = off && new Set(off);
  for (const page of state.pages.values()) {
    for (const row of page) {
      if (set.has(row.number)) {
        row[flag] = true;
      } else if (!clear || clear.has(row.number)) {
        delete row[flag];
      }
    }
  }
}

/** The selected frames in view order, one per line. */
export async function copyFrameNumbers() {
  try {
    const res = await rpc("view_frames", { frames: selectedFrames(), ...orderParams() }).promise;
    copy(res.frames.join("\n"));
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

function afterMarksChanged() {
  vscode.postMessage({ type: "marks", count: state.markCount });
  updateStatus();
  scheduleRender();
}

/** Ctrl+M: mark the selected packets, or unmark them if all of them are marked. */
export async function toggleMark() {
  const frames = selectedFrames();
  if (!frames.length) {
    showNotice("Select a packet to mark.");
    return;
  }
  try {
    const res = await rpc("mark_packets", { frames }).promise;
    patchMarks(res.marked, res.unmarked);
    state.markCount = res.count;
    afterMarksChanged();
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

async function unmarkAll() {
  try {
    await rpc("unmark_all", {}).promise;
    patchRows("marked", [], null);
    state.markCount = 0;
    afterMarksChanged();
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

/**
 * Ctrl+D: ignore the selected packets (left out of statistics and exports),
 * or stop ignoring them if all of them are ignored.
 * @param {boolean} [all] unignore every packet instead
 */
export async function toggleIgnore(all = false) {
  const frames = selectedFrames();
  if (!all && !frames.length) {
    showNotice("Select a packet to ignore.");
    return;
  }
  try {
    if (all) {
      await rpc("unignore_all", {}).promise;
      patchRows("ignored", [], null);
      state.ignoredCount = 0;
    } else {
      const res = await rpc("ignore_packets", { frames }).promise;
      patchRows("ignored", res.ignored, res.unignored);
      state.ignoredCount = res.count;
    }
    updateStatus();
    scheduleRender();
    void loadExpertSummary(); // the status bar's counts leave them out too
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

/** @param {"next" | "previous"} direction */
async function stepMark(direction) {
  if (!state.markCount) {
    showNotice("No packets are marked. Mark packets with Ctrl+M.");
    return;
  }
  try {
    const res = await rpc("find_packet", {
      mode: "marked",
      from: state.selectedFrame,
      direction,
      ...orderParams(),
    }).promise;
    if (res.frame === null || res.frame === undefined) {
      showNotice("None of the marked packets is displayed with the current filter.");
      return;
    }
    jumpToIndex(res.index, res.frame, true);
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

export function toggleTimeReference() {
  const frame = state.selectedFrame;
  if (frame === null) {
    showNotice("Select a packet to use as the time reference.");
    return;
  }
  state.timeRef = state.timeRef === frame ? null : frame;
  updateStatus();
  refreshRows();
}

/** Viewer actions from the command palette, keybindings and menus. @param {string} command */
export function runCommand(command) {
  switch (command) {
    case "find":
      openFind();
      break;
    case "findNext":
      void find("next");
      break;
    case "findPrevious":
      void find("previous");
      break;
    case "goBack":
      void goHistory("back");
      break;
    case "goForward":
      void goHistory("forward");
      break;
    case "nextInConversation":
      void stepConversation("next");
      break;
    case "previousInConversation":
      void stepConversation("previous");
      break;
    case "firstPacket":
      if (state.total) {
        jumpToIndex(0, null, true);
      }
      break;
    case "lastPacket":
      if (state.total) {
        jumpToIndex(state.total - 1, null, true);
      }
      break;
    case "selectAll":
      void selectAll();
      break;
    case "toggleMark":
      void toggleMark();
      break;
    case "nextMark":
      void stepMark("next");
      break;
    case "previousMark":
      void stepMark("previous");
      break;
    case "unmarkAll":
      void unmarkAll();
      break;
    case "toggleIgnore":
      void toggleIgnore();
      break;
    case "unignoreAll":
      void toggleIgnore(true);
      break;
    case "toggleTimeReference":
      toggleTimeReference();
      break;
    case "editPacketComment":
      editComment();
      break;
    case "deletePacketComment":
      if (state.selectedFrame !== null) {
        deleteComment(state.selectedFrame);
      }
      break;
    case "buildFilter":
      openFilterBuilder();
      break;
    case "showShortcuts":
      openShortcuts();
      break;
  }
}

// Keys VS Code leaves to a focused webview are handled here. Keys it binds
// globally (Ctrl+M, Ctrl+T, Ctrl+, …) are package.json keybindings that come
// back as "command" messages, so nothing runs twice.
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "f") {
    e.preventDefault();
    openFind();
  } else if (e.key === "F3") {
    e.preventDefault();
    void find(e.shiftKey ? "previous" : "next");
  } else if (mod && (e.key === "Home" || e.key === "End")) {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.tagName !== "INPUT" && t.tagName !== "SELECT") {
      e.preventDefault();
      runCommand(e.key === "Home" ? "firstPacket" : "lastPacket");
    }
  }
});

el.statusTime.addEventListener("click", () => vscode.postMessage({ type: "pickTimeFormat" }));
el.captureStop.addEventListener("click", () => vscode.postMessage({ type: "stopCapture" }));
el.statusNames.addEventListener("click", () => vscode.postMessage({ type: "pickNameResolution" }));
el.statusLua.addEventListener("click", () => vscode.postMessage({ type: "pickLuaDissectors" }));
