// @ts-check
/** Filter autocompletion (fields, operators, history, saved filters). */

import { cancelRpc, el, lib, rpc, state, vscode } from "./core.js";
import { applyFilter, showFilterError, validateSoon } from "./filterbar.js";
import { askAi, leaveAskMode } from "./ai.js";

/**
 * One dropdown serves two modes:
 * - "complete": field/protocol/operator completions for the word at the cursor
 * - "saved": saved filters, recent filters and "Save current filter…"
 *
 * - "ai": validated suggestions from "✨ Ask AI" (picking one fills the filter bar)
 *
 * @typedef {{label: string, detail?: string, desc?: string, kind: "field" | "protocol" | "operator" | "saved" | "recent" | "action" | "ai", value: string}} SuggestItem
 */
export const suggest = {
  /** @type {SuggestItem[]} */ items: [],
  index: -1,
  /** @type {"complete" | "saved" | "ai" | null} */ mode: null,
  /** @type {{kind: string, prefix: string, start: number, end: number} | null} */ ctx: null,
  seq: 0,
  /** @type {number | null} */ request: null,
};

const MAX_SUGGESTIONS = 50;
let suggestTimer = 0;

/** @param {boolean} explicit shown on Ctrl+Space even with an empty prefix */
function suggestSoon(explicit = false) {
  window.clearTimeout(suggestTimer);
  suggestTimer = window.setTimeout(() => void updateSuggestions(explicit), explicit ? 0 : 60);
}

/** @param {boolean} explicit */
async function updateSuggestions(explicit) {
  const text = el.filterInput.value;
  const cursor = el.filterInput.selectionStart ?? text.length;
  if (!text.trim() && explicit) {
    showSavedMenu();
    return;
  }
  const ctx = lib.completionContext(text, cursor);
  const seq = ++suggest.seq;
  if (ctx.kind === "operator" || ctx.kind === "logical") {
    // Only offer operators right after a space (or when asked), not while typing a value.
    const typedSpace = ctx.prefix === "" && /\s$/.test(text.slice(0, cursor));
    if (!explicit && !typedSpace && ctx.prefix === "") {
      hideSuggest();
      return;
    }
    const items = lib.operatorSuggestions(ctx.kind, ctx.prefix).map((/** @type {any} */ o) => ({
      label: o.label,
      desc: o.desc,
      kind: "operator",
      value: o.label,
    }));
    renderSuggest(items, "complete", ctx);
    return;
  }
  if (ctx.kind !== "field" || (!ctx.prefix && !explicit)) {
    hideSuggest();
    return;
  }
  if (suggest.request !== null) {
    cancelRpc(suggest.request);
  }
  const req = rpc("field_index", { prefix: ctx.prefix, limit: MAX_SUGGESTIONS });
  suggest.request = req.id;
  try {
    const res = await req.promise;
    if (seq !== suggest.seq) {
      return;
    }
    /** @type {SuggestItem[]} */
    const items = [
      ...res.protocols.map((/** @type {any} */ p) => ({
        label: p.name,
        detail: "protocol",
        desc: p.desc,
        kind: "protocol",
        value: p.name,
      })),
      ...res.fields.map((/** @type {any} */ f) => ({
        label: f.name,
        detail: lib.friendlyType(f.type),
        desc: f.blurb ? `${f.desc} — ${f.blurb}` : f.desc,
        kind: "field",
        value: f.name,
      })),
    ];
    // An exact match first, then protocols before fields (both lists are sorted).
    items.sort(
      (a, b) =>
        Number(b.value.toLowerCase() === ctx.prefix.toLowerCase()) -
        Number(a.value.toLowerCase() === ctx.prefix.toLowerCase()),
    );
    if (items.length === 1 && items[0].value === ctx.prefix) {
      hideSuggest(); // already complete
      return;
    }
    renderSuggest(items.slice(0, MAX_SUGGESTIONS), "complete", ctx);
  } catch {
    /* suggestions are best-effort */
  } finally {
    if (suggest.request === req.id) {
      suggest.request = null;
    }
  }
}

export function showSavedMenu() {
  // Supersede any pending or in-flight completion update.
  window.clearTimeout(suggestTimer);
  suggest.seq++;
  const current = el.filterInput.value.trim();
  /** @type {SuggestItem[]} */
  const items = [];
  if (current) {
    items.push({ label: "Save this filter…", desc: current, kind: "action", value: "save" });
  }
  for (const f of state.savedFilters) {
    items.push({
      label: f.name,
      detail: "saved",
      desc: f.filter,
      kind: "saved",
      value: f.filter,
    });
  }
  const savedValues = new Set(state.savedFilters.map((f) => f.filter));
  for (const h of state.history.slice(0, 15)) {
    if (!savedValues.has(h)) {
      items.push({ label: h, detail: "recent", kind: "recent", value: h });
    }
  }
  items.push({ label: "Manage saved filters…", kind: "action", value: "manage" });
  renderSuggest(items, "saved", null);
}

/**
 * @param {SuggestItem[]} items
 * @param {"complete" | "saved" | "ai"} mode
 * @param {any} ctx
 */
export function renderSuggest(items, mode, ctx) {
  if (!items.length) {
    hideSuggest();
    return;
  }
  suggest.items = items;
  suggest.mode = mode;
  suggest.ctx = ctx;
  // Nothing is preselected: Enter keeps meaning "apply the filter" unless the
  // user picked a suggestion with the arrow keys; Tab takes the first one.
  suggest.index = -1;
  el.suggest.replaceChildren(
    ...items.map((item, i) => {
      const row = document.createElement("div");
      row.className = `suggest-item kind-${item.kind}`;
      row.id = `suggest-${i}`;
      row.setAttribute("role", "option");
      row.dataset.index = String(i);
      const label = document.createElement("span");
      label.className = "suggest-label";
      label.textContent = item.label;
      row.append(label);
      if (item.detail) {
        const detail = document.createElement("span");
        detail.className = "suggest-detail";
        detail.textContent = item.detail;
        row.append(detail);
      }
      if (item.desc) {
        const desc = document.createElement("span");
        desc.className = "suggest-desc";
        desc.textContent = item.desc;
        row.title = item.desc;
        row.append(desc);
      }
      return row;
    }),
  );
  el.suggest.classList.remove("hidden");
  el.filterInput.setAttribute("aria-expanded", "true");
  highlightSuggestion();
}

export function hideSuggest() {
  window.clearTimeout(suggestTimer);
  suggest.seq++;
  suggest.items = [];
  suggest.mode = null;
  suggest.index = -1;
  el.suggest.classList.add("hidden");
  el.suggest.replaceChildren();
  el.filterInput.setAttribute("aria-expanded", "false");
  el.filterInput.removeAttribute("aria-activedescendant");
}

function highlightSuggestion() {
  [...el.suggest.children].forEach((row, i) => row.classList.toggle("active", i === suggest.index));
  const active = suggest.index >= 0 ? el.suggest.children[suggest.index] : null;
  if (active) {
    active.scrollIntoView({ block: "nearest" });
    el.filterInput.setAttribute("aria-activedescendant", active.id);
  } else {
    el.filterInput.removeAttribute("aria-activedescendant");
  }
}

/** @param {number} index */
function acceptSuggestion(index) {
  const item = suggest.items[index];
  const mode = suggest.mode;
  const ctx = suggest.ctx;
  hideSuggest();
  if (!item) {
    return;
  }
  if (item.kind === "action") {
    if (item.value === "save") {
      vscode.postMessage({ type: "saveFilter", expr: el.filterInput.value.trim() });
    } else {
      vscode.postMessage({ type: "manageSavedFilters" });
    }
    return;
  }
  if (mode === "saved") {
    el.filterInput.value = item.value;
    void applyFilter(item.value);
    return;
  }
  if (mode === "ai") {
    // Into the filter bar, not applied: Enter applies as usual.
    el.filterInput.value = item.value;
    el.filterInput.focus();
    el.filterInput.setSelectionRange(item.value.length, item.value.length);
    validateSoon();
    return;
  }
  const res = lib.applyCompletion(el.filterInput.value, ctx, item.value, item.kind === "operator");
  el.filterInput.value = res.text;
  el.filterInput.focus();
  el.filterInput.setSelectionRange(res.cursor, res.cursor);
  validateSoon();
}

el.filterInput.addEventListener("input", () => {
  if (state.ai.asking) {
    return; // a description, not a filter: no validation or completions
  }
  validateSoon();
  suggestSoon(false);
});
el.filterInput.addEventListener("keydown", (e) => {
  if (state.ai.asking) {
    if (e.key === "Enter") {
      e.preventDefault();
      askAi();
    } else if (e.key === "Escape") {
      e.preventDefault();
      leaveAskMode(true);
      showFilterError("");
    }
    return;
  }
  const open = suggest.items.length > 0;
  if (e.key === " " && e.ctrlKey) {
    e.preventDefault();
    suggestSoon(true);
  } else if (open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
    e.preventDefault();
    const n = suggest.items.length;
    suggest.index = e.key === "ArrowDown" ? (suggest.index + 1) % n : (suggest.index - 1 + n) % n;
    highlightSuggestion();
  } else if (open && (e.key === "Tab" || (e.key === "Enter" && suggest.index >= 0))) {
    e.preventDefault();
    acceptSuggestion(Math.max(0, suggest.index));
  } else if (e.key === "Enter") {
    e.preventDefault();
    hideSuggest();
    void applyFilter(el.filterInput.value);
  } else if (e.key === "Escape") {
    if (open) {
      hideSuggest();
    } else {
      el.filterInput.value = state.appliedFilter;
      validateSoon();
    }
  } else if (e.key === "ArrowDown" && e.altKey) {
    el.viewport.focus();
  } else if (e.key === "ArrowDown" && !el.filterInput.value.trim()) {
    e.preventDefault();
    showSavedMenu();
  }
});
// Caret moves (click, Home/End) change the context; close stale completions.
el.filterInput.addEventListener("click", () => {
  if (suggest.mode === "complete") {
    hideSuggest();
  }
});
el.filterInput.addEventListener("blur", () =>
  window.setTimeout(() => {
    if (document.activeElement !== el.filterInput && document.activeElement !== el.filterSaved) {
      hideSuggest();
    }
  }, 150),
);
// mousedown (not click) so the input keeps focus.
el.suggest.addEventListener("mousedown", (e) => {
  e.preventDefault();
  const row = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest(".suggest-item")
  );
  if (row) {
    acceptSuggestion(Number(row.dataset.index));
  }
});
el.filterSaved.addEventListener("mousedown", (e) => e.preventDefault());
el.filterSaved.addEventListener("click", () => {
  if (suggest.mode === "saved") {
    hideSuggest();
  } else {
    el.filterInput.focus();
    showSavedMenu();
  }
});
