// @ts-check
/**
 * Packet-list columns (layout, widths, sorting, resizing) and the backend's
 * progress events: indexing, live capture and streaming filters.
 */

import {
  CUSTOM_WIDTH,
  DEFAULT_WIDTHS,
  NUMERIC_IDS,
  PAGE_SIZE,
  el,
  icon,
  lib,
  state,
} from "./core.js";
import { FILTER_BUSY, setBusy } from "./host.js";
import { refreshRows, resetView, scheduleRender, updateSpacer } from "./list.js";
import { relocateSelection } from "./comments.js";
import { applyFilter, showFilterError, showNotice } from "./filterbar.js";
import { loadExpertSummary, persist, updateStatus } from "./status.js";

/** @returns {Column[]} */
export function columns() {
  return [
    ...state.baseColumns,
    ...state.customColumns.map((c) => ({
      id: `custom:${c.field}`,
      title: c.title,
      field: c.field,
      custom: true,
    })),
  ];
}

/** Visible columns in display order, each with its cell index in a row. */
export function visibleColumns() {
  return lib.layoutColumns(columns(), state.layout);
}

/** @param {Column} c */
function columnWidth(c) {
  return c.id === "info"
    ? "minmax(200px, 1fr)"
    : `${state.widths[c.id] ?? DEFAULT_WIDTHS[/** @type {keyof typeof DEFAULT_WIDTHS} */ (c.id)] ?? CUSTOM_WIDTH}px`;
}

export function applyColumnWidths() {
  el.list.style.setProperty(
    "--cols",
    visibleColumns()
      .map((v) => columnWidth(v.column))
      .join(" "),
  );
}

export function rebuildColumns() {
  const cols = visibleColumns().map((v) => v.column);
  applyColumnWidths();
  el.header.replaceChildren(
    ...cols.map((c) => {
      const cell = document.createElement("div");
      cell.className = "list-row-cell" + (NUMERIC_IDS.has(c.id) ? " num" : "");
      cell.setAttribute("role", "columnheader");
      cell.title = `${c.field} (drag to reorder, right-click for options)`;
      cell.dataset.id = c.id;
      cell.draggable = true;
      cell.append(c.title);
      if (state.sort && state.sort.field === c.field) {
        cell.setAttribute("aria-sort", state.sort.desc ? "descending" : "ascending");
        const ind = icon(state.sort.desc ? "triangle-down" : "triangle-up");
        ind.classList.add("sort-indicator");
        cell.append(ind);
      }
      cell.addEventListener("click", (e) => {
        if (/** @type {HTMLElement} */ (e.target).classList.contains("resize-handle")) {
          return;
        }
        toggleSort(c.field);
      });
      if (c.id !== "info") {
        const handle = document.createElement("div");
        handle.className = "resize-handle";
        handle.addEventListener("mousedown", (e) => startColumnResize(e, c.id, cell));
        cell.append(handle);
      }
      return cell;
    }),
  );
  el.header.className = "list-row";
  el.header.setAttribute("aria-rowindex", "1");
  // Row elements are rebuilt with the new column count on next render.
  el.rows.replaceChildren();
}

/**
 * Remove custom columns tshark doesn't know (e.g. a typo added in settings
 * while the file is open) and reload the visible pages without them.
 * @param {string[]} fields
 */
export function dropColumns(fields) {
  const bad = new Set(fields);
  state.customColumns = state.customColumns.filter((c) => !bad.has(c.field));
  if (state.sort && bad.has(state.sort.field)) {
    state.sort = null;
  }
  showFilterError(
    `Unknown field${fields.length > 1 ? "s" : ""} removed from columns: ${fields.join(", ")}`,
    true,
  );
  rebuildColumns();
  resetView({ keepSelection: true });
}

/**
 * The list grew (streaming open or filter) to `total` rows: the rows already
 * shown stay, and the last page, cut short where the list ended, is fetched again.
 * @param {number} total
 */
function growList(total) {
  state.total = total;
  state.matchCount = total;
  const prefix = `${state.viewKey}#`;
  for (const [key, page] of [...state.pages.entries()]) {
    if (key.startsWith(prefix) && page.length < PAGE_SIZE) {
      state.pages.delete(key);
    }
  }
  updateSpacer();
  scheduleRender();
}

/**
 * The filtered view's match count from an index event (streaming open): the
 * matches among the packets indexed so far.
 * @param {{filterId: number, matchCount: number} | undefined} view
 */
function viewCount(view) {
  return state.appliedFilter && view && view.filterId === state.filterId ? view.matchCount : null;
}

/**
 * More rows are indexed (streaming open): grow the list. A resumed open first
 * re-reads the rows it shows ("catching-up"); `restarted` means those didn't
 * match and indexing started over.
 * @param {{frames: number, fraction: number | null, view?: {filterId: number, matchCount: number}, phase?: string, resumedAt?: number, restarted?: boolean}} msg
 */
export function onIndexProgress(msg) {
  if (!state.indexing || !state.info) {
    return;
  }
  const frames = Number(msg.frames) || 0;
  const view = msg.view;
  // Live capture: while the end of the list is in view, it stays in view.
  const follow = !!state.capture?.running && atListEnd();
  state.info.frames = frames;
  state.indexFraction = typeof msg.fraction === "number" ? msg.fraction : null;
  const wasResuming = state.indexPhase === "catching-up";
  state.indexPhase = msg.phase === "catching-up" ? "catching-up" : "indexing";
  if (typeof msg.resumedAt === "number") {
    state.resumedAt = msg.resumedAt;
  }
  if (msg.restarted) {
    // A resumed open's saved rows no longer matched: indexed again from scratch.
    state.resumedAt = null;
    const matches = viewCount(view);
    state.total = state.appliedFilter ? (matches ?? 0) : frames;
    state.matchCount = state.total;
    updateSpacer();
    refreshRows();
    updateStatus();
    return;
  }
  const matches = viewCount(view);
  if (!state.appliedFilter) {
    growList(frames);
  } else if (matches !== null && matches !== state.total) {
    growList(matches);
  }
  if (wasResuming && state.indexPhase === "indexing") {
    refreshRows(); // the rows shown at once get their colors by now
  }
  if (follow) {
    el.viewport.scrollTop = el.viewport.scrollHeight;
  }
  updateStatus();
}

/** Whether the list is scrolled to its end (or is too short to scroll). */
function atListEnd() {
  const vp = el.viewport;
  return vp.scrollTop + vp.clientHeight >= vp.scrollHeight - state.rowHeight * 1.5;
}

/**
 * The backend's "capture" notification: statistics while capturing, then "stopped".
 * @param {any} msg
 */
export function onCaptureEvent(msg) {
  const capture = state.capture;
  if (!capture) {
    return;
  }
  capture.packets = Number(msg.packets) || capture.packets;
  capture.bytes = Number(msg.bytes) || capture.bytes;
  capture.seconds = Number(msg.seconds) || capture.seconds;
  if (msg.event === "stopped") {
    capture.running = false;
    capture.dropped = typeof msg.dropped === "number" ? msg.dropped : null;
    if (msg.error) {
      showNotice(`The capture stopped: ${msg.error}`);
    }
  }
  tickCapture();
}

let captureTimer = 0;
/** Show the capture's state in the status bar (and keep its clock running). */
export function tickCapture() {
  clearTimeout(captureTimer);
  const capture = state.capture;
  el.statusCapture.classList.toggle("hidden", !capture);
  if (!capture) {
    return;
  }
  const on = capture.interfaces.join(", ");
  el.statusCapture.classList.toggle("stopped", !capture.running);
  el.statusCapture.title = capture.filter ? `Capture filter: ${capture.filter}` : "";
  if (!capture.running) {
    // What was captured, until the capture is reloaded as a plain file.
    const dropped = capture.dropped ? ` · ${capture.dropped.toLocaleString()} dropped` : "";
    el.captureText.textContent = `Captured on ${on} in ${lib.formatDuration(capture.seconds)}${dropped}`;
    return;
  }
  const seconds = Math.max(capture.seconds, Date.now() / 1000 - capture.startedAt);
  el.captureText.textContent = `Capturing on ${on} · ${lib.formatDuration(seconds)} · ${lib.formatBytes(capture.bytes)}`;
  captureTimer = window.setTimeout(tickCapture, 1000);
}

/**
 * The index pass ended (streaming open).
 * @param {any} info @param {string | undefined} error @param {{filterId: number, matchCount: number}} [view]
 */
export function onIndexDone(info, error, view) {
  state.indexing = false;
  state.indexFraction = null;
  state.indexPhase = "indexing";
  state.resumedAt = null;
  state.info = info;
  const captured = !!state.capture;
  if (state.capture) {
    state.capture.running = false;
    tickCapture();
  }
  const matches = viewCount(view);
  if (!state.appliedFilter) {
    state.total = info.frames;
    state.matchCount = info.frames;
  } else if (matches !== null) {
    state.total = matches;
    state.matchCount = matches;
  }
  updateSpacer();
  refreshRows(); // columns and time formats that waited for the whole index
  updateStatus();
  void loadExpertSummary();
  if (error) {
    showNotice(`Indexing stopped after ${info.frames.toLocaleString()} packets: ${error}`);
  }
  if (captured && state.appliedFilter) {
    // The filter only saw the packets captured by the time it ran: run it again.
    void applyFilter(state.appliedFilter);
  }
}

/**
 * A streaming filter's "filter" event: more matches, or its end.
 * @param {{event: string, filterId: number, matchCount: number, fraction?: number | null, message?: string}} ev
 */
export function onFilterEvent(ev) {
  if (ev.filterId !== state.filterId) {
    if (ev.filterId > state.filterId) {
      state.earlyFilterEvents.set(ev.filterId, ev); // its set_filter result is on the way
    }
    return;
  }
  if (!state.filtering) {
    return;
  }
  if (ev.event === "progress") {
    state.filterFraction = ev.fraction ?? null;
    setBusy(FILTER_BUSY, true, state.filterFraction);
    if (ev.matchCount !== state.total) {
      growList(ev.matchCount);
    }
    updateStatus();
    return;
  }
  state.filtering = false;
  state.filterFraction = null;
  state.filterPartial = ev.event !== "done";
  setBusy(FILTER_BUSY, false);
  el.filterCancel.classList.add("hidden");
  state.total = ev.matchCount;
  state.matchCount = ev.matchCount;
  if (state.sort) {
    resetView({ keepSelection: true }); // the sort applies now
  } else {
    growList(ev.matchCount);
    if (state.selectedFrame !== null && state.selectedIndex === null) {
      void relocateSelection(); // it may have been found since
    }
  }
  updateStatus();
  const found = `${ev.matchCount.toLocaleString()} match${ev.matchCount === 1 ? "" : "es"}`;
  if (ev.event === "stopped") {
    showNotice(`Filter stopped: showing the ${found} found so far.`);
  } else if (ev.event === "failed") {
    showNotice(
      `The filter stopped early (${ev.message ?? "tshark failed"}): showing the ${found} found so far.`,
    );
  }
}

/** @param {string} field */
function toggleSort(field) {
  if (!state.ready) {
    return;
  }
  if (state.indexing) {
    showNotice(
      state.capture
        ? "Sorting is available when the capture stops."
        : "Sorting is available when indexing finishes.",
    );
    return;
  }
  if (state.filtering) {
    showNotice("The list is sorted when the filter finishes.");
  }
  if (!state.sort || state.sort.field !== field) {
    state.sort = { field, desc: false };
  } else if (!state.sort.desc) {
    state.sort = { field, desc: true };
  } else {
    state.sort = null;
  }
  rebuildColumns();
  resetView({ keepSelection: true });
}

export let resizing = false;

/** @param {MouseEvent} e @param {string} id @param {HTMLElement} cell */
function startColumnResize(e, id, cell) {
  e.preventDefault();
  e.stopPropagation();
  const startX = e.clientX;
  const startW = cell.getBoundingClientRect().width;
  /** @param {MouseEvent} ev */
  const move = (ev) => {
    state.widths[id] = Math.max(30, Math.round(startW + ev.clientX - startX));
    applyColumnWidths();
  };
  resizing = true;
  const up = () => {
    resizing = false;
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", up);
    persist();
  };
  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", up);
}
