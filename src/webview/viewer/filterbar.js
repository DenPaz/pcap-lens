// @ts-check
/** The display filter bar: validation, history, saved filters, notices. */

import {
  CANCELLED,
  INVALID_FILTER,
  announce,
  cancelRpc,
  el,
  lib,
  rpc,
  state,
  vscode,
} from "./core.js";
import { FILTER_BUSY, setBusy } from "./host.js";
import { onFilterEvent } from "./columns.js";
import { resetView } from "./list.js";
import { hideSuggest } from "./autocomplete.js";
import { askAi, leaveAskMode } from "./ai.js";
import { updateStatus } from "./status.js";
import { setFilterSpan } from "./filterpaint.js";

/**
 * The line under the filter bar: an error (the filter's, a failed request)
 * or, with `info`, a notice, each with its icon; "" hides it.
 * @param {string} message @param {boolean} [info]
 */
export function showFilterError(message, info = false) {
  const mark = document.createElement("span");
  mark.className = `codicon codicon-${info ? "info" : "error"}`;
  mark.setAttribute("aria-hidden", "true");
  const text = document.createElement("span");
  text.className = "notice-text";
  text.textContent = message;
  el.filterError.replaceChildren(...(message ? [mark, text] : []));
  el.filterError.classList.toggle("hidden", !message);
  el.filterError.dataset.info = info ? "1" : "";
}

/**
 * A validation error found while the suggestions are open: the expression is
 * usually half-typed ("ip.s"), so its line waits for the list to close
 * (`releaseHeldError`) and shows only if the text is the same and still
 * wrong. The box's own red tint and underline show at once.
 */
let held = { expr: "", error: "" };

export function releaseHeldError() {
  const { expr, error } = held;
  held = { expr: "", error: "" };
  if (
    error &&
    el.filterInput.value.trim() === expr &&
    el.filterInput.classList.contains("invalid") &&
    el.filterError.dataset.info !== "1"
  ) {
    showFilterError(error);
  }
}

export let validateTimer = 0;
export function validateSoon() {
  window.clearTimeout(validateTimer);
  validateTimer = window.setTimeout(validateNow, 250);
}

async function validateNow() {
  if (state.ai.asking) {
    return; // the input holds a description, not a filter
  }
  const expr = el.filterInput.value.trim();
  const seq = ++state.validateSeq;
  if (!expr) {
    el.filterInput.classList.remove("valid", "invalid");
    if (el.filterError.dataset.info !== "1") {
      showFilterError(""); // (an emptied box clears a validation error, not a notice)
    }
    return;
  }
  if (!state.ready) {
    return;
  }
  try {
    const res = await rpc("validate_filter", { expr }).promise;
    if (seq !== state.validateSeq || state.ai.asking) {
      return;
    }
    el.filterInput.classList.toggle("valid", res.valid);
    el.filterInput.classList.toggle("invalid", !res.valid);
    const error = res.valid ? "" : lib.filterErrorText(res.error, expr);
    el.filterInput.title = error;
    setFilterSpan(res.valid ? null : res.span, expr);
    held = { expr: "", error: "" };
    if (!res.valid && !el.suggest.classList.contains("hidden")) {
      held = { expr, error };
      if (el.filterError.dataset.info !== "1") {
        showFilterError(""); // (an older error of the text being typed)
      }
    } else if (!res.valid) {
      showFilterError(error);
    } else if (el.filterError.dataset.info !== "1") {
      showFilterError(""); // a valid filter clears a validation error, not a notice
    }
  } catch {
    /* validation is best-effort */
  }
}

/** @param {string} raw */
/** Tell screen readers how many packets the applied filter shows. */
export function announceFilter() {
  const frames = state.info?.frames ?? 0;
  const text = lib.filterAnnouncement(state.appliedFilter, state.matchCount, frames);
  if (text) {
    announce(text);
  }
}

export async function applyFilter(raw) {
  const expr = raw.trim();
  if (!state.ready) {
    return;
  }
  if (state.filterRequest !== null) {
    cancelRpc(state.filterRequest);
  }
  // Applying validates too: drop the typing's pending validation, which would
  // otherwise land later and clear whatever the message area shows by then.
  window.clearTimeout(validateTimer);
  state.validateSeq++;
  showFilterError("");
  // Streaming: the first matches come back at once, the rest as "filter" events.
  const req = rpc("set_filter", { expr, stream: true });
  state.filterRequest = req.id;
  el.filterCancel.classList.remove("hidden");
  setBusy(req.id, true);
  try {
    const res = await req.promise;
    if (state.filterRequest !== req.id) {
      return; // a newer filter was applied meanwhile: its reply decides
    }
    if (res.expr !== state.appliedFilter) {
      state.previousFilter = state.appliedFilter;
    }
    state.appliedFilter = res.expr;
    state.filterId = res.filterId;
    state.total = res.matchCount;
    state.matchCount = res.matchCount;
    state.filtering = !!res.filtering;
    state.filterFraction = res.fraction ?? null;
    state.filterPartial = !!res.partial;
    setBusy(FILTER_BUSY, state.filtering, state.filterFraction);
    el.filterInput.classList.remove("invalid");
    el.filterInput.classList.toggle("valid", !!expr);
    vscode.postMessage({ type: "filterApplied", expr });
    resetView({ keepSelection: true });
    updateStatus();
    if (!state.filtering) {
      announceFilter(); // (a streaming filter says so when it is done)
    }
    const early = state.earlyFilterEvents.get(res.filterId);
    state.earlyFilterEvents.clear();
    if (early) {
      onFilterEvent(early);
    }
  } catch (err) {
    const e = /** @type {any} */ (err);
    if (e?.code === CANCELLED) {
      return;
    }
    el.filterInput.classList.remove("valid");
    el.filterInput.classList.add("invalid");
    showFilterError(
      e?.code === INVALID_FILTER
        ? lib.filterErrorText(e.message, expr)
        : `Filter failed: ${e?.message ?? e}`,
    );
    setFilterSpan(e?.code === INVALID_FILTER ? e.data?.span : null, expr);
  } finally {
    if (state.filterRequest === req.id) {
      state.filterRequest = null;
      el.filterCancel.classList.toggle("hidden", !state.filtering); // ■ now stops the filter
    }
  }
}

el.filterApply.addEventListener("click", () => {
  if (state.ai.asking) {
    askAi();
    return;
  }
  hideSuggest();
  void applyFilter(el.filterInput.value);
});
el.filterClear.addEventListener("click", () => {
  leaveAskMode(false);
  el.filterInput.value = "";
  el.filterInput.classList.remove("valid", "invalid");
  hideSuggest();
  void applyFilter("");
});
el.filterCancel.addEventListener("click", () => {
  if (state.filterRequest !== null) {
    cancelRpc(state.filterRequest);
  } else if (state.filtering) {
    void rpc("stop_filter", { filterId: state.filterId }).promise.catch(() => undefined);
  }
});

/** @param {string[]} history */
export function setHistory(history) {
  state.history = history || [];
}

/**
 * An info line under the filter bar, optionally with one action button.
 * @param {string} message @param {{label: string, run: () => void}} [action]
 */
export function showNotice(message, action) {
  showFilterError(message, true);
  if (action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "notice-action secondary";
    button.textContent = action.label;
    button.addEventListener("click", () => {
      showFilterError("");
      action.run();
    });
    el.filterError.append(button);
  }
}
