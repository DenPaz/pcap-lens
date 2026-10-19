// @ts-check
/**
 * What the packet list shows when it has no rows (lib.emptyState): a filter
 * still looking or matching nothing, with what to try next (clear it, go back
 * to the previous one, edit or build one) and the backend's filter_hints (a
 * field no packet has, a case-sensitive comparison); a live capture waiting
 * for its first packet; a capture without packets.
 */

import { CANCELLED, cancelRpc, el, icon, lib, rpc, state, vscode } from "./core.js";
import { applyFilter } from "./filterbar.js";
import { openFilterBuilder } from "./builder.js";

/** The state the panel was drawn for (redrawn only when it changes). */
let drawnKey = "";
/** filter_hints results by expression, and the request in flight. */
/** @type {Map<string, any>} */
const hintCache = new Map();
/** @type {{expr: string, id: number} | null} */
let hintRequest = null;

export function renderEmpty() {
  const view = lib.emptyState({
    ready: state.ready,
    total: state.total,
    filter: state.appliedFilter,
    filtering: state.filtering,
    fraction: state.filterFraction,
    partial: state.filterPartial,
    indexing: state.indexing,
    capture: state.capture,
  });
  el.empty.classList.toggle("hidden", !view);
  if (!view) {
    drawnKey = "";
    return;
  }
  const hints = hintCache.get(state.appliedFilter);
  const key = JSON.stringify([view, state.appliedFilter, state.previousFilter, !!hints]);
  if (key === drawnKey) {
    return;
  }
  drawnKey = key;
  draw(view, hints);
  if (view.kind === "no-match" && !hints && !state.indexing) {
    loadHints(state.appliedFilter);
  }
}

/**
 * @param {{kind: string, title: string, detail: string}} view @param {any} hints
 */
function draw(view, hints) {
  const box = document.createElement("div");
  box.className = "empty-box";
  const title = document.createElement("p");
  title.className = "empty-title";
  title.textContent = view.title;
  box.append(title);
  if (view.kind === "no-match" || view.kind === "searching") {
    const code = document.createElement("code");
    code.className = "empty-filter";
    code.textContent = state.appliedFilter;
    box.append(code);
  }
  if (view.detail) {
    const detail = document.createElement("p");
    detail.className = "empty-detail";
    detail.textContent = view.detail;
    box.append(detail);
  }
  if (view.kind === "no-match") {
    box.append(actions(), hintList(hints));
  }
  el.empty.replaceChildren(box);
}

/** @param {string} label @param {() => void} run @param {string} [glyph] @param {string} [title] */
function button(label, run, glyph, title) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "secondary";
  if (glyph) {
    b.append(icon(glyph), " ");
  }
  b.append(label);
  if (title) {
    b.title = title;
  }
  b.addEventListener("click", run);
  return b;
}

function clearFilter() {
  el.filterInput.value = "";
  el.filterInput.classList.remove("valid", "invalid");
  void applyFilter("");
}

function actions() {
  const row = document.createElement("div");
  row.className = "empty-actions";
  row.append(button("Clear Filter", clearFilter, "clear-all"));
  const prev = state.previousFilter;
  if (prev && prev !== state.appliedFilter) {
    row.append(
      button(
        "Previous Filter",
        () => {
          el.filterInput.value = prev;
          void applyFilter(prev);
        },
        "arrow-left",
        `Apply the filter used before: ${prev}`,
      ),
    );
  }
  row.append(
    button(
      "Edit Filter",
      () => {
        el.filterInput.focus();
        el.filterInput.select();
      },
      "edit",
    ),
    button("Build Filter…", () => openFilterBuilder({}), "list-filter"),
  );
  return row;
}

/** @param {any} hints */
function hintList(hints) {
  const list = document.createElement("ul");
  list.className = "empty-hints";
  if (state.filtering || state.indexing) {
    return list;
  }
  if (!hints) {
    const item = document.createElement("li");
    item.className = "empty-checking";
    item.textContent = "Checking which of the filter's fields occur in the capture…";
    list.append(item);
    return list;
  }
  if (hints.error) {
    return list; // (hints are a bonus: a failure just shows none)
  }
  for (const hint of lib.filterHintItems(hints)) {
    const item = document.createElement("li");
    if (hint.type === "missing") {
      item.append(
        `No packet in this capture has ${hint.names.length === 1 ? "" : "any of "}`,
        ...codeList(hint.names),
        ". ",
        button(
          "Protocol Hierarchy",
          () =>
            vscode.postMessage({
              type: "runCommand",
              id: "pcapViewer.statistics.protocolHierarchy",
            }),
          "type-hierarchy",
          "See which protocols the capture has",
        ),
      );
    } else if (hint.type === "case") {
      const code = document.createElement("code");
      code.textContent = hint.filter;
      const asked = document.createElement("code");
      asked.textContent = `${hint.field} == "${hint.value}"`;
      item.append(
        asked,
        " is case-sensitive. Try ",
        code,
        " ",
        button("Apply", () => {
          el.filterInput.value = hint.filter;
          void applyFilter(hint.filter);
        }),
      );
    } else {
      item.append("Every field occurs in the capture, but no packet has the values asked for. ");
      for (const name of hint.names) {
        item.append(
          button(
            `Values of ${name}…`,
            () => openFilterBuilder({ field: name }),
            undefined,
            `See the values ${name} takes`,
          ),
          " ",
        );
      }
    }
    list.append(item);
  }
  return list;
}

/** "a", "a and b", "a, b and c" as code elements. @param {string[]} names */
function codeList(names) {
  /** @type {(string | HTMLElement)[]} */
  const out = [];
  names.forEach((name, i) => {
    if (i) {
      out.push(i === names.length - 1 ? " or " : ", ");
    }
    const code = document.createElement("code");
    code.textContent = name;
    out.push(code);
  });
  return out;
}

/** @param {string} expr */
function loadHints(expr) {
  if (hintRequest?.expr === expr) {
    return;
  }
  if (hintRequest) {
    cancelRpc(hintRequest.id);
  }
  const req = rpc("filter_hints", { expr });
  hintRequest = { expr, id: req.id };
  req.promise
    .then((res) => hintCache.set(expr, res))
    .catch((err) => {
      if (err?.code !== CANCELLED) {
        hintCache.set(expr, { error: String(err?.message ?? err) });
      }
    })
    .finally(() => {
      if (hintRequest?.id === req.id) {
        hintRequest = null;
      }
      renderEmpty();
    });
}

/** A new capture (or reload): hints of the old one no longer apply. */
export function resetEmptyHints() {
  hintCache.clear();
  if (hintRequest) {
    cancelRpc(hintRequest.id);
    hintRequest = null;
  }
  drawnKey = "";
}
