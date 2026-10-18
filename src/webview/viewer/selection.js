// @ts-check
/** Single and multi-selection in the packet list, Select All and Copy. */

import {
  COPY_CHUNK,
  MAX_COPY_ROWS,
  MAX_SELECTION,
  PAGE_SIZE,
  el,
  lib,
  rpc,
  state,
} from "./core.js";
import { visibleColumns } from "./columns.js";
import { orderParams, rowAt, scheduleRender } from "./list.js";
import { showComment } from "./comments.js";
import { loadDetail, postSelection, reportSelection } from "./detail.js";
import { copy } from "./contextmenu.js";
import { showNotice } from "./filterbar.js";
import { updateStatus } from "./status.js";

el.rows.addEventListener("mousedown", (e) => {
  const rowEl = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".list-row")
  );
  if (!rowEl || rowEl.dataset.index === undefined || e.button !== 0) {
    return; // right-click: the context menu decides (it keeps a multi-selection)
  }
  const index = Number(rowEl.dataset.index);
  if (e.shiftKey) {
    e.preventDefault(); // no text selection
    void selectRange(index, e.ctrlKey || e.metaKey);
  } else if (e.ctrlKey || e.metaKey) {
    toggleInSelection(index);
  } else {
    selectIndex(index);
  }
});

el.viewport.addEventListener("keydown", (e) => {
  if (!state.ready || state.total === 0 || e.ctrlKey || e.metaKey || e.altKey) {
    return; // Ctrl+Home/End etc. are handled document-wide
  }
  const pageRows = Math.max(1, Math.floor(el.viewport.clientHeight / state.rowHeight) - 1);
  const cur = state.selectedIndex ?? -1;
  /** @type {Record<string, number>} */
  const moves = {
    ArrowDown: cur + 1,
    ArrowUp: cur - 1,
    PageDown: cur + pageRows,
    PageUp: cur - pageRows,
    Home: 0,
    End: state.total - 1,
  };
  if (e.key in moves) {
    e.preventDefault();
    const target = Math.max(0, Math.min(state.total - 1, moves[e.key]));
    if (e.shiftKey) {
      void selectRange(target, false);
    } else {
      selectIndex(target);
    }
  } else if (e.key === "Escape" && state.selection.size) {
    setSelection(new Set());
  } else if (e.key === "Enter" || e.key === "ArrowRight") {
    e.preventDefault();
    el.tree.focus();
  }
});

/** Select one row (dropping a multi-selection). @param {number} index @param {boolean} [center] */
export function selectIndex(index, center = false) {
  state.anchorIndex = index;
  if (state.selection.size) {
    setSelection(new Set());
  }
  focusIndex(index, center);
}

/** Move the focused row (the one the detail pane shows) without changing the selection. @param {number} index @param {boolean} [center] */
export function focusIndex(index, center = false) {
  state.selectedIndex = index;
  scrollIndexIntoView(index, center);
  const row = rowAt(index);
  state.selectedFrame = row ? row.number : null;
  if (row) {
    selectFrame(row.number);
  }
  scheduleRender();
}

/** Frames the row actions (mark, copy, export) apply to: the multi-selection, else the focused row. */
export function selectedFrames() {
  if (state.selection.size) {
    return [...state.selection];
  }
  return state.selectedFrame !== null ? [state.selectedFrame] : [];
}

/** @param {Set<number>} frames the new multi-selection (one frame or none = single selection) */
export function setSelection(frames) {
  state.selection = frames.size > 1 ? frames : new Set();
  state.selectionFilterId = state.filterId;
  postSelection();
  updateStatus();
  scheduleRender();
}

/** Ctrl/Cmd+click: add a row to the selection, or take it out. @param {number} index */
function toggleInSelection(index) {
  const row = rowAt(index);
  if (!row) {
    return;
  }
  const next = new Set(selectedFrames());
  state.anchorIndex = index;
  if (!next.has(row.number)) {
    next.add(row.number);
    setSelection(next);
    focusIndex(index);
    return;
  }
  if (next.size === 1) {
    return; // the last selected row stays selected
  }
  next.delete(row.number);
  setSelection(next);
  if (row.number === state.selectedFrame) {
    void focusFrame(next.values().next().value ?? row.number); // focus another selected row
  }
}

/** Focus a frame of the current view by number (no scrolling). @param {number} frame */
async function focusFrame(frame) {
  try {
    const viewKey = state.viewKey;
    const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
    if (
      res.filterId === state.filterId &&
      viewKey === state.viewKey &&
      typeof res.index === "number"
    ) {
      focusIndex(res.index);
    }
  } catch {
    /* ignore */
  }
}

/**
 * Shift+click / Shift+arrows: select the rows from the anchor to `index`
 * (added to the selection with Ctrl). Rows not loaded yet come from the backend.
 * @param {number} index @param {boolean} add
 */
async function selectRange(index, add) {
  const anchor = state.anchorIndex ?? state.selectedIndex ?? index;
  state.anchorIndex = anchor;
  const lo = Math.min(anchor, index);
  const count = Math.min(Math.max(anchor, index) - lo + 1, MAX_SELECTION);
  const base = add ? selectedFrames() : [];
  const seq = ++state.rangeSeq;
  focusIndex(index);
  /** @type {number[]} */
  let frames = [];
  for (let i = lo; i < lo + count; i++) {
    const row = rowAt(i);
    if (!row) {
      frames = [];
      break;
    }
    frames.push(row.number);
  }
  if (!frames.length) {
    try {
      const viewKey = state.viewKey;
      const res = await rpc("view_frames", { offset: lo, limit: count, ...orderParams() }).promise;
      if (seq !== state.rangeSeq || res.filterId !== state.filterId || viewKey !== state.viewKey) {
        return;
      }
      frames = res.frames;
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
      return;
    }
  }
  if (count === MAX_SELECTION) {
    showNotice(`Selected the first ${MAX_SELECTION.toLocaleString()} packets of the range.`);
  }
  setSelection(new Set([...base, ...frames]));
}

let selectAllPending = false;
/** Ctrl+A: every packet of the current view (in the filter bar or find box: its text). */
export async function selectAll() {
  const active = /** @type {HTMLElement | null} */ (document.activeElement);
  if (active?.tagName === "INPUT" || active?.tagName === "TEXTAREA") {
    /** @type {HTMLInputElement} */ (active).select();
    return;
  }
  const all = Math.min(state.total, MAX_SELECTION);
  if (
    !state.ready ||
    state.total === 0 ||
    selectAllPending ||
    (all > 1 && state.selection.size === all)
  ) {
    return; // (the key and VS Code's Select All command can both arrive)
  }
  selectAllPending = true;
  const filterId = state.filterId;
  try {
    const res = await rpc("view_frames", {
      offset: 0,
      limit: Math.min(state.total, MAX_SELECTION),
      ...orderParams(),
    }).promise;
    if (res.filterId !== filterId) {
      return;
    }
    if (state.selectedIndex === null) {
      focusIndex(0);
    }
    setSelection(new Set(res.frames));
    if (state.total > MAX_SELECTION) {
      showNotice(`Selected the first ${MAX_SELECTION.toLocaleString()} packets.`);
    }
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  } finally {
    selectAllPending = false;
  }
}

// Ctrl+A / Cmd+A. VS Code's webview doesn't stop the key, so Chromium selects
// all of the page's text, and VS Code's own Select All runs execCommand("selectAll")
// in the webview (a package.json keybinding doesn't win over either). Both start
// with a cancelable selectstart on <body> (in an input its target is the input,
// which keeps its normal Ctrl+A): cancel it and select every packet instead.
let pointerDown = false; // a mouse drag can also start on <body>
document.addEventListener("mousedown", () => (pointerDown = true), true);
document.addEventListener("mouseup", () => (pointerDown = false), true);
document.addEventListener("selectstart", (e) => {
  if (e.target === document.body && !pointerDown) {
    e.preventDefault();
    void selectAll();
  }
});

/** Cached rows of `frames` in view order, or null if some aren't loaded. @param {Set<number>} frames */
function cachedRows(frames) {
  /** @type {{index: number, row: Row}[]} */
  const found = [];
  const prefix = `${state.viewKey}#`;
  for (const [key, page] of state.pages.entries()) {
    if (!key.startsWith(prefix)) {
      continue;
    }
    const first = Number(key.slice(prefix.length)) * PAGE_SIZE;
    page.forEach((/** @type {Row} */ row, /** @type {number} */ i) => {
      if (frames.has(row.number)) {
        found.push({ index: first + i, row });
      }
    });
  }
  if (found.length !== frames.size) {
    return null;
  }
  return found.sort((a, b) => a.index - b.index).map((f) => f.row);
}

/** The visible columns' titles and each row's cells, for copying. @param {Row[]} rows */
function copyText(rows) {
  const cols = visibleColumns();
  const cells = rows.map((r) => cols.map((c) => r.cells[c.index] ?? ""));
  return lib.rowsToText(
    cols.map((c) => c.column.title),
    cells,
    rows.length > 1,
  );
}

/** Copy the selected rows (visible columns, view order); rows not loaded come from the backend. */
export async function copyRows() {
  const frames = selectedFrames();
  if (!frames.length) {
    return;
  }
  const cached = cachedRows(new Set(frames));
  if (cached) {
    copy(copyText(cached));
    return;
  }
  const viewKey = state.viewKey;
  try {
    const ordered = (await rpc("view_frames", { frames, ...orderParams() }).promise).frames.slice(
      0,
      MAX_COPY_ROWS,
    );
    /** @type {Row[]} */
    const rows = [];
    for (let i = 0; i < ordered.length; i += COPY_CHUNK) {
      const res = await rpc("list_packets", {
        frames: ordered.slice(i, i + COPY_CHUNK),
        columns: state.customColumns.map((c) => c.field),
        sort: state.sort,
        timeFormat: state.timeFormat,
        timeRef: state.timeRef,
      }).promise;
      if (viewKey !== state.viewKey) {
        return; // the view changed meanwhile
      }
      rows.push(...res.rows);
    }
    copy(copyText(rows));
    if (frames.length > MAX_COPY_ROWS) {
      showNotice(
        `Copied the first ${MAX_COPY_ROWS.toLocaleString()} rows. Export Packet List saves them all.`,
      );
    }
  } catch (err) {
    showNotice(String(/** @type {any} */ (err)?.message ?? err));
  }
}

// Ctrl+C in the packet list (VS Code turns it into a "copy" event in the webview).
document.addEventListener("copy", (e) => {
  const active = document.activeElement;
  if (!active || !el.viewport.contains(active) || !selectedFrames().length) {
    return;
  }
  e.preventDefault();
  const cached = cachedRows(new Set(selectedFrames()));
  if (cached && e.clipboardData) {
    e.clipboardData.setData("text/plain", copyText(cached));
  } else {
    void copyRows();
  }
});

/** @param {number} index @param {boolean} center */
export function scrollIndexIntoView(index, center) {
  const top = lib.scrollTopForIndex({
    index,
    scrollTop: el.viewport.scrollTop,
    viewportHeight: el.viewport.clientHeight,
    total: state.total,
    rowHeight: state.rowHeight,
    center,
  });
  if (Math.abs(top - el.viewport.scrollTop) >= 1) {
    el.viewport.scrollTop = top;
  }
}

let detailTimer = 0;
/** @param {number} frame */
export function selectFrame(frame) {
  reportSelection(frame);
  state.selectedFrame = frame;
  updateStatus();
  window.clearTimeout(detailTimer);
  // Debounce so holding an arrow key doesn't start a tshark run per row.
  detailTimer = window.setTimeout(() => {
    void loadDetail(frame);
    void showComment(frame);
  }, 60);
}
