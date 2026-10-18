// @ts-check
/**
 * The packet diagram: the details pane's other view (Tree | Diagram), with
 * each protocol's header drawn as rows of 32 bits, one cell per field
 * (lib.packetDiagram lays it out). Cells are buttons: picking one selects
 * its field in the tree (and so its bytes), and the selected field's cell is
 * marked whichever way it was selected.
 */

import { el, lib, state } from "./core.js";
import { showTreeMenu } from "./contextmenu.js";
import { nodeIndex, revealPath } from "./detail.js";
import { persist } from "./status.js";

/** @typedef {ReturnType<typeof lib.packetDiagram>[number]} DiagramProtocol */
/** @typedef {DiagramProtocol["rows"][number]["cells"][number]} DiagramCell */

/** The detail drawn last (redrawn when another one is shown). @type {any} */
let drawn = null;
/** Each field cell's protocol and field nodes. @type {Map<HTMLElement, {proto: any, node: any}>} */
const cellNodes = new Map();

el.viewTree.addEventListener("click", () => setDetailView("tree"));
el.viewDiagram.addEventListener("click", () => setDetailView("diagram"));
el.diagramValues.addEventListener("click", () => {
  state.diagramValues = !state.diagramValues;
  persist();
  drawn = null;
  applyDetailView();
});

/** @param {"tree" | "diagram"} view */
export function setDetailView(view) {
  state.detailView = view;
  persist();
  applyDetailView();
  (view === "diagram" ? firstFocusableCell() : el.tree)?.focus();
}

/** Show the chosen view (drawing the diagram if the detail changed since). */
export function applyDetailView() {
  const diagram = state.detailView === "diagram";
  el.detailViews.classList.toggle("hidden", !state.detail);
  el.viewTree.setAttribute("aria-pressed", String(!diagram));
  el.viewDiagram.setAttribute("aria-pressed", String(diagram));
  el.diagramValues.classList.toggle("hidden", !diagram);
  el.diagramValues.setAttribute("aria-pressed", String(state.diagramValues));
  el.tree.classList.toggle("hidden", diagram);
  el.diagram.classList.toggle("hidden", !diagram || !state.detail);
  if (diagram && state.detail && drawn !== state.detail) {
    drawDiagram();
  }
}

/** Forget the diagram (no packet selected). */
export function clearDiagram() {
  drawn = null;
  cellNodes.clear();
  el.diagram.replaceChildren();
  applyDetailView();
}

function drawDiagram() {
  drawn = state.detail;
  cellNodes.clear();
  const protocols = lib.packetDiagram(state.detail.tree);
  if (!protocols.length) {
    const empty = document.createElement("div");
    empty.className = "pd-empty";
    empty.textContent = "No protocol header to draw for this packet.";
    el.diagram.replaceChildren(empty);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const p of protocols) {
    frag.append(drawProtocol(p));
  }
  el.diagram.replaceChildren(frag);
  markDiagramSelection();
}

/** @param {DiagramProtocol} p */
function drawProtocol(p) {
  const box = document.createElement("div");
  box.className = "pd-proto";
  box.setAttribute("role", "group");
  box.setAttribute("aria-label", p.title);
  const title = document.createElement("div");
  title.className = "pd-title";
  title.textContent = p.title;
  title.setAttribute("aria-hidden", "true");
  const grid = document.createElement("div");
  grid.className = "pd-grid";
  for (let bit = 0; bit < lib.DIAGRAM_BITS; bit += 8) {
    const ruler = document.createElement("div");
    ruler.className = "pd-ruler";
    ruler.setAttribute("aria-hidden", "true");
    ruler.style.gridColumn = `${bit + 2} / span 8`;
    ruler.textContent = String(bit);
    grid.append(ruler);
  }
  p.rows.forEach((row, r) => {
    const gridRow = String(r + 2);
    const offset = document.createElement("div");
    offset.className = "pd-offset";
    offset.setAttribute("aria-hidden", "true");
    offset.style.gridRow = gridRow;
    const elided = row.cells.some((c) => c.rows > 1);
    offset.textContent = `${row.offset / 8}${elided ? "…" : ""}`;
    grid.append(offset);
    for (const c of row.cells) {
      const cell = drawCell(p, c);
      cell.style.gridRow = gridRow;
      cell.style.gridColumn = `${c.col + 2} / span ${c.width}`;
      grid.append(cell);
    }
  });
  box.append(title, grid);
  if (p.more) {
    const more = document.createElement("div");
    more.className = "pd-more";
    more.textContent = "(The rest of this protocol isn't drawn: see the tree.)";
    box.append(more);
  }
  return box;
}

/**
 * @param {DiagramProtocol} p
 * @param {DiagramCell} c
 */
function drawCell(p, c) {
  if (c.item < 0) {
    const gap = document.createElement("div");
    gap.className = "pd-cell gap";
    gap.title = "Bits no field describes";
    gap.setAttribute("aria-hidden", "true");
    return gap;
  }
  const item = p.items[c.item];
  const cell = document.createElement("button");
  cell.type = "button";
  cell.className = "pd-cell" + (c.cont ? " cont" : "") + (c.rows > 1 ? " elided" : "");
  cell.tabIndex = -1;
  const text = state.diagramValues && item.value ? `${item.name}: ${item.value}` : item.name;
  cell.textContent = text;
  const bits = item.len === 1 ? "1 bit" : `${item.len} bits`;
  const where =
    item.len % 8 === 0 && item.start % 8 === 0
      ? `${item.len / 8} byte${item.len === 8 ? "" : "s"} at byte ${item.start / 8}`
      : `${bits} at bit ${item.start}`;
  const label = item.value ? `${item.name}: ${item.value}` : item.name;
  cell.title =
    `${item.node.label}\n${where}` + (c.rows > 1 ? ` (${c.rows} rows shown as one)` : "");
  cell.setAttribute("aria-label", `${label}, ${where}${c.cont ? " (continued)" : ""}`);
  cell.dataset.node = String(item.node.id);
  if (!c.cont) {
    cell.dataset.first = "1";
  }
  cellNodes.set(cell, { proto: p.node, node: item.node });
  return cell;
}

/** Mark the cells of the selected field (or of the diagram field it belongs to). */
export function markDiagramSelection() {
  if (!drawn) {
    return;
  }
  const entry = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
  const ids = new Set((entry?.path ?? []).map((n) => String(n.id)));
  /** @type {HTMLElement | null} */
  let focusable = null;
  for (const cell of cellNodes.keys()) {
    const selected = ids.has(cell.dataset.node ?? "");
    cell.classList.toggle("selected", selected);
    if (selected) {
      cell.setAttribute("aria-current", "true");
    } else {
      cell.removeAttribute("aria-current");
    }
    if (selected && cell.dataset.first && !focusable) {
      focusable = cell;
    }
  }
  // One cell takes Tab (the selected field's, else the first); arrows move between fields.
  focusable = focusable ?? firstFocusableCell();
  for (const cell of cellNodes.keys()) {
    cell.tabIndex = cell === focusable ? 0 : -1;
  }
}

function firstFocusableCell() {
  return /** @type {HTMLElement | null} */ (el.diagram.querySelector(".pd-cell[data-first]"));
}

/** Select a cell's field in the tree (expanding it there), which marks its bytes and cell. */
/** @param {HTMLElement} cell */
function pick(cell) {
  const found = cellNodes.get(cell);
  if (found) {
    revealPath([found.proto, found.node]);
  }
  return found;
}

el.diagram.addEventListener("click", (e) => {
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest("button.pd-cell")
  );
  if (cell) {
    pick(cell);
  }
});

el.diagram.addEventListener("contextmenu", (e) => {
  const cell = /** @type {HTMLElement | null} */ (
    /** @type {HTMLElement} */ (e.target).closest("button.pd-cell")
  );
  const found = cell && pick(cell);
  const entry = found && nodeIndex.get(found.node.id);
  if (entry) {
    e.preventDefault();
    showTreeMenu(entry, e.clientX, e.clientY);
  }
});

el.diagram.addEventListener("keydown", (e) => {
  const cells = /** @type {HTMLElement[]} */ ([
    ...el.diagram.querySelectorAll(".pd-cell[data-first]"),
  ]);
  const at = cells.indexOf(/** @type {HTMLElement} */ (document.activeElement));
  /** @type {number} */
  let next;
  switch (e.key) {
    case "ArrowRight":
    case "ArrowDown":
      next = at + 1;
      break;
    case "ArrowLeft":
    case "ArrowUp":
      next = at - 1;
      break;
    case "Home":
      next = 0;
      break;
    case "End":
      next = cells.length - 1;
      break;
    default:
      return;
  }
  e.preventDefault();
  const cell = cells[Math.max(0, Math.min(cells.length - 1, next))];
  if (cell) {
    pick(cell);
    cell.focus();
  }
});

applyDetailView();
