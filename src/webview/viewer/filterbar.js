// @ts-check
/** The display filter bar: validation, history, saved filters, notices. */

import { CANCELLED, INVALID_FILTER, cancelRpc, el, rpc, state, vscode } from "./core.js";
import { FILTER_BUSY, setBusy } from "./host.js";
import { onFilterEvent } from "./columns.js";
import { resetView } from "./list.js";
import { hideSuggest } from "./autocomplete.js";
import { askAi, leaveAskMode } from "./ai.js";
import { updateStatus } from "./status.js";

/** @param {string} message @param {boolean} [info] */
export function showFilterError(message, info = false) {
  el.filterError.textContent = message;
  el.filterError.classList.toggle("hidden", !message);
  el.filterError.dataset.info = info ? "1" : "";
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
    el.filterInput.title = res.valid ? "" : res.error;
    if (!res.valid) {
      showFilterError(res.error);
    } else if (el.filterError.dataset.info !== "1") {
      showFilterError(""); // a valid filter clears a validation error, not a notice
    }
  } catch {
    /* validation is best-effort */
  }
}

/** @param {string} raw */
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
    showFilterError(e?.code === INVALID_FILTER ? e.message : `Filter failed: ${e?.message ?? e}`);
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
