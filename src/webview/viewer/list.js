// @ts-check
/** The virtualized packet list: paging, rendering, scrolling and the view (filter, sort). */

import {
  CANCELLED,
  MAX_INFLIGHT_PAGES,
  NUMERIC_IDS,
  PAGE_SIZE,
  cancelRpc,
  el,
  lib,
  rpc,
  state,
} from "./core.js";
import { dropColumns, visibleColumns } from "./columns.js";
import { selectFrame, setSelection } from "./selection.js";
import { relocateSelection } from "./comments.js";
import { showFilterError } from "./filterbar.js";

function computeViewKey() {
  return [
    state.filterId,
    state.sort ? `${state.sort.field}:${state.sort.desc}` : "",
    state.customColumns.map((c) => c.field).join(","),
    state.coloring?.id ?? 0,
    state.timeFormat,
    state.timeRef ?? "",
  ].join("|");
}

/** The view's order, sent with every request that deals in row indexes (the backend applies it first). */
export function orderParams() {
  return { sort: state.sort, timeFormat: state.timeFormat };
}

/** Refetch the visible rows in place (same order and scroll position), e.g. after new colors. */
export function refreshRows() {
  for (const id of state.inflightPages.values()) {
    cancelRpc(id);
  }
  state.inflightPages.clear();
  state.pages.clear();
  state.viewKey = computeViewKey();
  render();
}

/** Drop cached pages (filter, sort or columns changed) and re-render. */
export function resetView(opts = { keepSelection: false }) {
  for (const id of state.inflightPages.values()) {
    cancelRpc(id);
  }
  state.inflightPages.clear();
  state.pages.clear();
  state.viewKey = computeViewKey();
  updateSpacer();
  state.anchorIndex = null; // row indexes changed
  if (state.selection.size && state.selectionFilterId !== state.filterId) {
    setSelection(new Set()); // a new filter drops a multi-selection (a new sort keeps it)
  }
  if (opts.keepSelection && state.selectedFrame !== null) {
    state.selectedIndex = null; // unknown until the backend says where it moved
    void relocateSelection();
  } else {
    el.viewport.scrollTop = 0;
  }
  render();
}

export function updateSpacer() {
  const win = lib.computeWindow({
    scrollTop: 0,
    viewportHeight: el.viewport.clientHeight,
    total: state.total,
    rowHeight: state.rowHeight,
  });
  el.spacer.style.height = `${win.virtualHeight}px`;
  el.empty.classList.toggle("hidden", !state.ready || state.total > 0);
}

/** @param {number} index @returns {Row | undefined} */
export function rowAt(index) {
  const page = state.pages.get(`${state.viewKey}#${Math.floor(index / PAGE_SIZE)}`);
  return page ? page[index % PAGE_SIZE] : undefined;
}

let renderQueued = false;
export function scheduleRender() {
  if (!renderQueued) {
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      render();
    });
  }
}

function render() {
  if (!state.ready) {
    return;
  }
  const theme = lib.themeKind(document.body.classList);
  const win = lib.computeWindow({
    scrollTop: el.viewport.scrollTop,
    viewportHeight: el.viewport.clientHeight,
    total: state.total,
    rowHeight: state.rowHeight,
  });
  el.rows.style.transform = `translateY(${win.top}px)`;
  el.viewport.setAttribute("aria-rowcount", String(state.total + 1));
  const cols = visibleColumns();
  // Reuse row elements (pooling keeps scrolling cheap).
  while (el.rows.children.length < win.count) {
    const row = document.createElement("div");
    row.className = "list-row";
    row.setAttribute("role", "row");
    for (let i = 0; i < cols.length; i++) {
      const cell = document.createElement("div");
      cell.setAttribute("role", "gridcell");
      if (NUMERIC_IDS.has(cols[i].column.id)) {
        cell.className = "num";
      }
      row.append(cell);
    }
    // (Out of the grid: absolutely positioned. Shows a related packet's relation.)
    const mark = document.createElement("span");
    mark.className = "related-mark";
    mark.setAttribute("aria-hidden", "true");
    row.append(mark);
    el.rows.append(row);
  }
  while (el.rows.children.length > win.count) {
    el.rows.lastChild?.remove();
  }
  for (let i = 0; i < win.count; i++) {
    const index = win.first + i;
    const rowEl = /** @type {HTMLElement} */ (el.rows.children[i]);
    const row = rowAt(index);
    rowEl.dataset.index = String(index);
    rowEl.setAttribute("aria-rowindex", String(index + 2)); // (the header is row 1)
    rowEl.classList.toggle("odd", index % 2 === 1);
    rowEl.classList.toggle("loading", !row);
    const selected = index === state.selectedIndex || (!!row && state.selection.has(row.number));
    rowEl.classList.toggle("selected", selected);
    rowEl.classList.toggle("focused", index === state.selectedIndex && state.selection.size > 1);
    rowEl.setAttribute("aria-selected", String(selected));
    // Coloring rule colors, except on selected rows (they keep the theme's selection
    // colors), marked rows (the mark style wins) and ignored rows (drawn dimmed).
    rowEl.classList.toggle("marked", !!row?.marked);
    rowEl.classList.toggle("ignored", !!row?.ignored);
    rowEl.classList.toggle("has-comment", !!row?.comment);
    rowEl.classList.toggle("comment-edited", !!row?.commentEdited);
    const rule =
      !selected && !row?.marked && !row?.ignored ? lib.rowColors(row, state.coloring) : null;
    // Drawn for the theme (pcapViewer.coloringStyle): the colors as custom
    // properties, the way to use them as a class (styles.css).
    const look = rule ? lib.ruleStyle(rule, theme, state.coloringStyle) : null;
    rowEl.classList.toggle("colored", !!rule);
    for (const mode of ["full", "subtle", "stripe"]) {
      rowEl.classList.toggle(`rule-${mode}`, look?.mode === mode);
    }
    rowEl.style.setProperty("--rule-bg", rule ? rule.background : "");
    rowEl.style.setProperty("--rule-fg", rule ? rule.foreground : "");
    rowEl.style.setProperty("--rule-stripe", look ? look.stripe : "");
    markRelated(rowEl, row ? state.related.get(row.number) : undefined, !!row?.ignored);
    for (let c = 0; c < cols.length; c++) {
      const cell = /** @type {HTMLElement} */ (rowEl.children[c]);
      // Times arrive formatted by the backend (pcapViewer.timeFormat, time reference).
      const text = row ? (row.cells[cols[c].index] ?? "") : c === 0 ? "…" : "";
      if (cell.textContent !== text) {
        cell.textContent = text;
      }
      // A resolved name: the address as tooltip; the No. cell: the packet's comment.
      const tip =
        (row && cols[c].column.id === "number"
          ? row.comment
          : lib.cellAddress(cols[c].column, row)) ?? "";
      if (cell.title !== tip) {
        cell.title = tip;
      }
    }
  }
  requestPages(win.first, win.count);
}

/** What each related-packet mark means, relative to the selected packet. */
const RELATED = {
  request: ["arrow-right", "Request: the selected packet answers it"],
  response: ["arrow-left", "Response to the selected packet"],
  ack: ["check", "Acknowledged by the selected packet"],
  "dup-ack": ["check-all", "The selected packet is a duplicate ACK of it"],
  related: ["circle-small-filled", "Related to the selected packet"],
};

/** @param {HTMLElement} rowEl @param {string | undefined} kind @param {boolean} ignored */
function markRelated(rowEl, kind, ignored) {
  const mark = /** @type {HTMLElement} */ (rowEl.lastElementChild);
  const [glyph, text] = kind ? RELATED[/** @type {keyof RELATED} */ (kind)] : ["", ""];
  const cls = glyph ? `related-mark codicon codicon-${glyph}` : "related-mark";
  if (mark.className !== cls) {
    mark.className = cls;
    mark.title = text;
  }
  const description = [text, ignored ? "Ignored" : ""].filter(Boolean).join(". ");
  if (description) {
    rowEl.setAttribute("aria-description", description);
  } else {
    rowEl.removeAttribute("aria-description");
  }
}

/** @param {number} first @param {number} count */
function requestPages(first, count) {
  const pages = lib.pagesForRange(first, count, PAGE_SIZE, state.total, 1);
  const viewKey = state.viewKey;
  for (const page of pages) {
    const key = `${viewKey}#${page}`;
    if (
      state.pages.has(key) ||
      state.inflightPages.has(key) ||
      state.inflightPages.size >= MAX_INFLIGHT_PAGES
    ) {
      continue;
    }
    const req = rpc("list_packets", {
      offset: page * PAGE_SIZE,
      limit: PAGE_SIZE,
      columns: state.customColumns.map((c) => c.field),
      sort: state.sort,
      timeFormat: state.timeFormat,
      timeRef: state.timeRef,
    });
    state.inflightPages.set(key, req.id);
    req.promise.then(
      (res) => {
        state.inflightPages.delete(key);
        if (viewKey !== state.viewKey || res.filterId !== state.filterId) {
          return; // stale
        }
        if (res.rejectedColumns?.length) {
          dropColumns(res.rejectedColumns);
          return;
        }
        for (const row of res.rows) {
          row.cid = res.coloringId;
        }
        state.pages.set(key, res.rows);
        if (res.total !== state.total) {
          state.total = res.total;
          updateSpacer();
        }
        if (
          state.selectedIndex !== null &&
          state.selectedFrame === null &&
          Math.floor(state.selectedIndex / PAGE_SIZE) === page
        ) {
          const row = rowAt(state.selectedIndex);
          if (row) {
            selectFrame(row.number);
          }
        }
        scheduleRender();
      },
      (err) => {
        state.inflightPages.delete(key);
        if (err?.code !== CANCELLED && viewKey === state.viewKey) {
          showFilterError(`Could not load packets: ${err?.message ?? err}`);
        }
      },
    );
  }
}

el.viewport.addEventListener("scroll", scheduleRender, { passive: true });
// VS Code switches the theme class on <body> when the color theme changes;
// coloring rules are drawn for the theme kind.
new MutationObserver(() => scheduleRender()).observe(document.body, {
  attributes: true,
  attributeFilter: ["class"],
});

new ResizeObserver(() => {
  updateSpacer();
  scheduleRender();
}).observe(el.viewport);
