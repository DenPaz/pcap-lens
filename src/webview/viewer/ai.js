// @ts-check
/** Copilot filter help (✨): ask mode and its suggestions. */

import { el, state, vscode } from "./core.js";
import { showFilterError, validateTimer } from "./filterbar.js";
import { hideSuggest, renderSuggest } from "./autocomplete.js";

// "✨ Ask AI": the filter bar temporarily takes a description; the host asks
// the language model, validates the answers with tshark and sends back only
// valid filters, shown in the suggestion dropdown.
const FILTER_PLACEHOLDER = el.filterInput.placeholder;
const AI_PLACEHOLDER =
  "Describe the packets you want, e.g. DNS queries that got no answer (Enter to ask, Esc to cancel)";
let aiSeq = 0;

/** @param {boolean} available */
export function setAiAvailable(available) {
  state.ai.available = available;
  el.filterAi.classList.toggle("hidden", !available);
  if (!available && state.ai.asking) {
    leaveAskMode(true);
  }
}

function enterAskMode() {
  if (!state.ai.available || state.ai.asking) {
    return;
  }
  hideSuggest();
  // A validation still pending for the old filter text must not clear the AI messages.
  window.clearTimeout(validateTimer);
  state.validateSeq++;
  showFilterError("");
  state.ai.asking = true;
  state.ai.savedText = el.filterInput.value;
  state.ai.savedClasses = ["valid", "invalid"].filter((c) => el.filterInput.classList.contains(c));
  el.filterInput.classList.remove("valid", "invalid");
  el.filterInput.value = "";
  el.filterInput.placeholder = AI_PLACEHOLDER;
  el.filterField.classList.add("ai-mode");
  el.filterAi.setAttribute("aria-pressed", "true");
  el.filterInput.focus();
}

/** @param {boolean} restore put the filter text (and its validity) back */
export function leaveAskMode(restore) {
  if (!state.ai.asking) {
    return;
  }
  if (state.ai.request !== null) {
    vscode.postMessage({ type: "aiCancel", id: state.ai.request });
    state.ai.request = null;
  }
  state.ai.asking = false;
  el.filterField.classList.remove("ai-mode", "ai-busy");
  el.filterAi.setAttribute("aria-pressed", "false");
  el.filterInput.placeholder = FILTER_PLACEHOLDER;
  el.filterInput.readOnly = false;
  if (restore) {
    el.filterInput.value = state.ai.savedText;
    el.filterInput.classList.add(...state.ai.savedClasses);
  }
}

export function askAi() {
  const request = el.filterInput.value.trim();
  if (!request || state.ai.request !== null) {
    return;
  }
  state.ai.request = ++aiSeq;
  el.filterField.classList.add("ai-busy");
  el.filterInput.readOnly = true;
  showFilterError("Asking the language model… (Esc to cancel)", true);
  vscode.postMessage({ type: "aiSuggest", id: state.ai.request, request });
}

/** @param {{id: number, suggestions: {filter: string, explanation: string}[], message?: string}} msg */
export function onAiSuggestions(msg) {
  if (msg.id !== state.ai.request) {
    return; // cancelled or superseded
  }
  state.ai.request = null;
  leaveAskMode(true);
  el.filterInput.focus();
  if (!msg.suggestions.length) {
    showFilterError(msg.message || "No display filter suggestions.", true);
    return;
  }
  showFilterError("");
  renderSuggest(
    msg.suggestions.map((s) => ({
      label: s.filter,
      detail: "AI",
      desc: s.explanation,
      kind: "ai",
      value: s.filter,
    })),
    "ai",
    null,
  );
}

el.filterAi.addEventListener("mousedown", (e) => e.preventDefault());
el.filterAi.addEventListener("click", () => {
  if (state.ai.asking) {
    leaveAskMode(true);
    showFilterError("");
  } else {
    enterAskMode();
  }
});
