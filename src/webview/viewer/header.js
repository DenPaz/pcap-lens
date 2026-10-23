// @ts-check
/** The column header: its menu, hiding columns, drag to reorder and fit to contents. */

import { el, lib, state, vscode } from "./core.js";
import {
  applyColumnWidths,
  columns,
  rebuildColumns,
  resizing,
  setSort,
  visibleColumns,
} from "./columns.js";
import { scheduleRender } from "./list.js";
import { showMenu } from "./menu.js";
import { persist } from "./status.js";
/** @import { MenuEntry } from "./menu.js" */

/** @param {string} id */
const isHidden = (id) => state.layout.hidden.includes(id);

function saveLayout() {
  rebuildColumns();
  scheduleRender();
  vscode.postMessage({ type: "columnLayout", layout: state.layout });
}

/** @param {string} id @param {boolean} hidden */
function setHidden(id, hidden) {
  const next = hidden
    ? [...new Set([...state.layout.hidden, id])]
    : state.layout.hidden.filter((h) => h !== id);
  if (columns().every((c) => next.includes(c.id))) {
    return; // keep at least one column
  }
  state.layout = { ...state.layout, hidden: next };
  saveLayout();
}

/** Width of the widest header/cell text currently rendered in the column. @param {string} id */
function resizeToContents(id) {
  const pos = visibleColumns().findIndex((v) => v.column.id === id);
  if (pos < 0) {
    return;
  }
  const sample = /** @type {HTMLElement | null} */ (
    el.rows.firstElementChild?.children[pos] ?? el.header.children[pos] ?? null
  );
  const ctx = document.createElement("canvas").getContext("2d");
  if (!ctx || !sample) {
    return;
  }
  ctx.font = getComputedStyle(sample).font;
  let widest = ctx.measureText(visibleColumns()[pos].column.title).width + 16;
  for (const rowEl of el.rows.children) {
    widest = Math.max(widest, ctx.measureText(rowEl.children[pos]?.textContent ?? "").width);
  }
  state.widths[id] = Math.min(800, Math.max(40, Math.ceil(widest + 20)));
  applyColumnWidths();
  persist();
}

el.header.addEventListener("contextmenu", (e) => {
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest("[data-id]")
  );
  const col = cell ? columns().find((c) => c.id === cell.dataset.id) : undefined;
  if (!col) {
    return;
  }
  e.preventDefault();
  const visible = visibleColumns().length;
  const sorted = state.sort && state.sort.field === col.field ? state.sort : null;
  /** @type {MenuEntry[]} */
  const items = [
    {
      label: "Sort Ascending",
      icon: "arrow-up",
      checked: sorted ? !sorted.desc : false,
      action: () => setSort({ field: col.field, desc: false }),
    },
    {
      label: "Sort Descending",
      icon: "arrow-down",
      checked: sorted ? sorted.desc : false,
      action: () => setSort({ field: col.field, desc: true }),
    },
  ];
  if (state.sort) {
    items.push({ label: "Capture Order", icon: "list-ordered", action: () => setSort(null) });
  }
  items.push("-");
  if (visible > 1) {
    items.push({
      label: `Hide “${col.title}”`,
      icon: "eye-closed",
      action: () => setHidden(col.id, true),
    });
  }
  if (col.id !== "info") {
    items.push({
      label: "Resize to Contents",
      icon: "arrow-both",
      action: () => resizeToContents(col.id),
    });
  }
  if (col.custom) {
    items.push(
      {
        label: "Rename Column…",
        icon: "edit",
        action: () => vscode.postMessage({ type: "renameColumn", field: col.field }),
      },
      {
        label: "Remove Column",
        icon: "trash",
        action: () => vscode.postMessage({ type: "removeColumn", field: col.field }),
      },
    );
  }
  items.push(
    "-",
    {
      label: "Columns",
      icon: "list-flat",
      children: columns().map((c) => ({
        label: c.title,
        checked: !isHidden(c.id),
        action: !isHidden(c.id) && visible === 1 ? null : () => setHidden(c.id, !isHidden(c.id)),
      })),
    },
    {
      label: "Reset Column Widths",
      icon: "discard",
      action: () => {
        state.widths = {};
        applyColumnWidths();
        persist();
      },
    },
    {
      label: "Reset Column Order and Visibility",
      icon: "discard",
      action: () => {
        state.layout = { order: [], hidden: [] };
        saveLayout();
      },
    },
  );
  showMenu(e.clientX, e.clientY, items);
});

/** @type {string | null} */
let dragId = null;
const clearDragMarks = () =>
  [...el.header.children].forEach((c) => c.classList.remove("drag-over"));
el.header.addEventListener("dragstart", (e) => {
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest?.("[data-id]") ?? null
  );
  if (!cell || resizing) {
    e.preventDefault();
    return;
  }
  dragId = cell.dataset.id ?? null;
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", dragId ?? "");
  }
});
el.header.addEventListener("dragover", (e) => {
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest("[data-id]")
  );
  if (!dragId || !cell) {
    return;
  }
  e.preventDefault();
  clearDragMarks();
  if (cell.dataset.id !== dragId) {
    cell.classList.add("drag-over");
  }
});
el.header.addEventListener("drop", (e) => {
  e.preventDefault();
  clearDragMarks();
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest("[data-id]")
  );
  const moving = dragId;
  dragId = null;
  if (!moving || !cell || cell.dataset.id === moving) {
    return;
  }
  // Reorder over all columns (hidden ones keep their place), dropping in front of the target.
  const order = lib
    .layoutColumns(columns(), { order: state.layout.order })
    .map((/** @type {any} */ c) => c.column.id);
  state.layout = {
    ...state.layout,
    order: lib.moveColumn(order, moving, cell.dataset.id ?? null),
  };
  saveLayout();
});
el.header.addEventListener("dragend", () => {
  dragId = null;
  clearDragMarks();
});
