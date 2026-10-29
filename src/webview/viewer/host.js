// @ts-check
/** Messages from the extension host, and the progress bar. */

import { el, lib, rpc, rpcPending, state } from "./core.js";
import { hideOverlay, showOverlay } from "./overlay.js";
import {
  onCaptureEvent,
  onFilterEvent,
  onIndexDone,
  onIndexProgress,
  rebuildColumns,
  tickCapture,
} from "./columns.js";
import { refreshRows, resetView, scheduleRender, setRowHeight } from "./list.js";
import { gotoFrame, showComment } from "./comments.js";
import { clearDetail } from "./detail.js";
import { applyFilter, setHistory, validateSoon } from "./filterbar.js";
import { showSavedMenu, suggest } from "./autocomplete.js";
import { runCommand } from "./navigation.js";
import { resetEmptyHints } from "./empty.js";
import { leaveAskMode, onAiSuggestions, setAiAvailable } from "./ai.js";
import {
  loadExpertSummary,
  renderFilterButtons,
  resetExpert,
  setStatusText,
  onReplay,
  updateStatus,
} from "./status.js";

window.addEventListener("message", (event) => {
  // VS Code posts to this frame with its own origin as the target; ignore other senders.
  if (event.origin !== window.origin) {
    return;
  }
  const msg = event.data;
  switch (msg.type) {
    case "loading":
      showOverlay(msg.message, { progress: true });
      break;
    case "progress":
      onProgress(msg);
      break;
    case "init":
      onInit(msg);
      break;
    case "error":
      showOverlay(msg.message, { error: true, reload: msg.canReload });
      break;
    case "rpcResult": {
      const p = rpcPending.get(msg.id);
      rpcPending.delete(msg.id);
      setBusy(msg.id, false);
      p?.resolve(msg.result);
      break;
    }
    case "rpcError": {
      const p = rpcPending.get(msg.id);
      rpcPending.delete(msg.id);
      setBusy(msg.id, false);
      p?.reject(msg.error);
      break;
    }
    case "applyFilter":
      el.filterInput.value = msg.expr;
      void applyFilter(msg.expr);
      break;
    case "prepareFilter":
      el.filterInput.value = msg.expr;
      el.filterInput.focus();
      validateSoon();
      break;
    case "focusFilter":
      el.filterInput.focus();
      el.filterInput.select();
      break;
    case "goto":
      void gotoFrame(msg.number);
      break;
    case "columns":
      state.customColumns = msg.columns;
      state.layout = msg.layout || { order: [], hidden: [] };
      rebuildColumns();
      resetView({ keepSelection: true });
      break;
    case "timeFormat":
      state.timeFormat = msg.format;
      updateStatus();
      refreshRows();
      break;
    case "quickDetail":
      state.quickDetail = msg.quickDetail;
      break;
    case "coloringStyle":
      state.coloringStyle = msg.style;
      scheduleRender();
      break;
    case "listDensity":
      setRowHeight(lib.densityRowHeight(msg.density));
      break;
    case "indexProgress":
      onIndexProgress(msg);
      break;
    case "exportProgress":
      state.exportProgress = msg.done ? undefined : (msg.fraction ?? null);
      updateStatus();
      break;
    case "captureEvent":
      onCaptureEvent(msg);
      break;
    case "replay":
      onReplay(msg.replay);
      break;
    case "indexDone":
      onIndexDone(msg.info, msg.error, msg.view);
      break;
    case "filterEvent":
      onFilterEvent(msg);
      break;
    case "command":
      runCommand(msg.command);
      break;
    case "commentsChanged":
      refreshRows();
      void showComment(state.selectedFrame);
      break;
    case "history":
      setHistory(msg.history);
      break;
    case "savedFilters":
      state.savedFilters = msg.savedFilters || [];
      if (suggest.mode === "saved") {
        showSavedMenu();
      }
      break;
    case "coloring":
      state.coloring = msg.rules.length ? { id: msg.coloringId, rules: msg.rules } : null;
      state.colorized = msg.temporary ?? 0;
      state.coloringProgress = undefined;
      refreshRows();
      updateStatus();
      break;
    case "coloringProgress":
      state.coloringProgress = msg.done ? undefined : msg.fraction;
      updateStatus();
      break;
    case "aiAvailable":
      setAiAvailable(!!msg.available);
      break;
    case "commands":
      state.commands = Array.isArray(msg.commands) ? msg.commands : [];
      break;
    case "filterButtons":
      state.filterButtons = Array.isArray(msg.buttons) ? msg.buttons : [];
      renderFilterButtons();
      break;
    case "aiSuggestions":
      onAiSuggestions(msg);
      break;
  }
});

/** @param {any} msg */
function onInit(msg) {
  leaveAskMode(true);
  resetEmptyHints();
  state.info = msg.info;
  // The backend lists the seven base columns first, then any custom ones.
  state.baseColumns = msg.info.columns.slice(0, 7);
  // Only columns tshark accepted; unknown fields were dropped (with a warning) at open.
  state.customColumns = lib.acceptedColumns(msg.columns, msg.info.columns.slice(7));
  state.layout = msg.layout || { order: [], hidden: [] };
  state.timeFormat = msg.timeFormat || "relative";
  setStatusText(el.statusNames, msg.names || "");
  setStatusText(el.statusLua, msg.lua || "");
  state.quickDetail = msg.quickDetail || state.quickDetail;
  state.timeRef = null;
  state.markCount = 0;
  state.ignoredCount = 0;
  state.nav = { back: [], forward: [] };
  state.total = msg.info.frames;
  state.matchCount = msg.info.frames;
  state.filterId = msg.info.filterId;
  state.indexing = !!msg.info.indexing;
  state.indexFraction = null;
  state.resumedAt = state.indexing && msg.info.resumedAt ? msg.info.resumedAt : null;
  state.indexPhase = state.resumedAt ? "catching-up" : "indexing";
  state.exportProgress = undefined;
  const capture = msg.info.capture;
  state.capture = capture
    ? {
        running: !!capture.running,
        interfaces: capture.interfaces || [],
        filter: capture.filter || "",
        startedAt: capture.startedAt || Date.now() / 1000,
        packets: capture.packets || 0,
        bytes: capture.bytes || 0,
        seconds: 0,
        dropped: capture.dropped ?? null,
      }
    : null;
  tickCapture();
  state.filtering = false;
  state.filterFraction = null;
  state.filterPartial = false;
  state.earlyFilterEvents.clear();
  state.coloringProgress = undefined;
  state.ready = true;
  setHistory(msg.history);
  state.savedFilters = msg.savedFilters || [];
  // Warm the backend's field catalogue so the first suggestion is instant.
  rpc("field_index", { limit: 0 }).promise.catch(() => undefined);
  hideOverlay();
  rebuildColumns();
  clearDetail();
  state.selectedFrame = null;
  state.selectedIndex = null;
  state.selection = new Set();
  state.anchorIndex = null;
  busyRequests.clear();
  renderProgress();
  state.elapsedMs = msg.elapsedMs;
  const filter = msg.filter || el.filterInput.value.trim();
  if (filter) {
    el.filterInput.value = filter;
    void applyFilter(filter);
  } else {
    resetView();
  }
  updateStatus();
  if (state.indexing) {
    resetExpert(); // counted once the index is done (onIndexDone)
  } else {
    void loadExpertSummary();
  }
  el.viewport.focus();
}

/** @param {any} p */
function onProgress(p) {
  const fraction = typeof p.fraction === "number" ? p.fraction : null;
  if (!el.overlay.classList.contains("hidden")) {
    setProgress(el.overlayProgress, el.overlayFill, fraction);
    if (typeof p.frames === "number") {
      el.overlayDetail.textContent = `${p.frames.toLocaleString()} packets${fraction !== null ? ` · ${Math.round(fraction * 100)}%` : ""}`;
    }
  } else if (typeof p.id === "number" && rpcPending.has(p.id)) {
    setBusy(p.id, true, fraction);
  }
}

/**
 * The busy bar shows while a request that reported progress (a filter, a first
 * sort, a column extraction…) is running, and hides when the last one settles.
 */
/** Requests running (id → fraction, null if unknown). */
/** @type {Map<number, number | null>} */
const busyRequests = new Map();
/** Busy-bar id of a streaming filter after its set_filter request returned. */
export const FILTER_BUSY = -1;
/** @param {number} id @param {boolean} on @param {number | null} [fraction] */
export function setBusy(id, on, fraction = null) {
  if (on) {
    busyRequests.set(id, fraction);
  } else {
    busyRequests.delete(id);
  }
  renderProgress();
}

/** Show the most important work running in the progress bar (or hide it). */
export function renderProgress() {
  const busy = [...busyRequests.values()];
  const view = lib.progressView({
    index:
      state.indexing && !state.capture && state.info
        ? {
            phase: state.indexPhase,
            frames: state.info.frames,
            fraction: state.indexFraction,
            resumedAt: state.resumedAt,
          }
        : null,
    filter: state.filtering ? state.filterFraction : undefined,
    exporting: state.exportProgress,
    coloring: state.coloringProgress,
    busy: busy.length ? (busy.find((f) => f !== null) ?? null) : undefined,
  });
  const bar = el.busyBar;
  bar.classList.toggle("hidden", !view.visible);
  bar.classList.toggle("indeterminate", view.visible && view.fraction === null);
  bar.classList.toggle("secondary", view.secondary);
  bar.setAttribute("aria-label", view.label || "Progress");
  if (view.visible && view.fraction !== null) {
    bar.setAttribute("aria-valuenow", String(Math.round(view.fraction * 100)));
    el.busyFill.style.width = `${(view.fraction * 100).toFixed(1)}%`;
  } else {
    bar.removeAttribute("aria-valuenow"); // (indeterminate, or hidden)
    el.busyFill.style.width = "";
  }
}

/**
 * @param {HTMLElement} bar @param {HTMLElement} fill @param {number | null} fraction
 */
export function setProgress(bar, fill, fraction) {
  bar.classList.toggle("indeterminate", fraction === null);
  fill.style.width = fraction === null ? "" : `${Math.round(fraction * 100)}%`;
}
