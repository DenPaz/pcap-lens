// @ts-check
/** The status bar, persisted webview state and the filter buttons toolbar. */

import { TIME_LABELS, el, icon, lib, rpc, state, vscode } from "./core.js";
import { renderProgress } from "./host.js";
import { applyFilter } from "./filterbar.js";

/**
 * The filter-button bar: one button per `pcapViewer.filterButtons` entry
 * (click applies its filter; right-click, Shift+F10 or the context-menu key
 * asks the host to edit, move or remove it) and "+" to add the current
 * filter. Hidden while there are none (PCAP: Add Filter Button… adds the first).
 */
export function renderFilterButtons() {
  const bar = el.filterButtons;
  const buttons = state.filterButtons.map((b, index) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = "filter-button";
    node.textContent = b.label;
    node.title = lib.filterButtonTitle(b);
    node.dataset.index = String(index);
    node.addEventListener("click", () => {
      el.filterInput.value = b.filter;
      void applyFilter(b.filter);
    });
    const edit = () => vscode.postMessage({ type: "editFilterButton", index, filter: b.filter });
    // Shift+F10 and the menu key: Chromium turns them into "contextmenu" on
    // Windows and Linux but not on macOS, so they're handled here, and the
    // "contextmenu" that may follow them is ignored.
    let keyEditAt = -Infinity;
    node.addEventListener("keydown", (e) => {
      if ((e.key === "F10" && e.shiftKey) || e.key === "ContextMenu") {
        e.preventDefault();
        keyEditAt = Date.now();
        edit();
      }
    });
    node.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      if (Date.now() - keyEditAt > 1000) {
        edit();
      }
    });
    return node;
  });
  const add = document.createElement("button");
  add.type = "button";
  add.id = "filter-button-add";
  add.className = "icon";
  add.append(icon("add"));
  add.title = "Add a filter button for the display filter in the filter bar…";
  add.setAttribute("aria-label", "Add filter button");
  add.addEventListener("click", () =>
    vscode.postMessage({ type: "addFilterButton", filter: el.filterInput.value.trim() }),
  );
  bar.replaceChildren(...buttons, add);
  bar.classList.toggle("hidden", !buttons.length);
  updateFilterButtons();
}

/** Marks the buttons whose filter is the applied one. */
function updateFilterButtons() {
  const applied = state.appliedFilter.trim();
  for (const node of el.filterButtons.querySelectorAll("button.filter-button")) {
    const b = state.filterButtons[Number(/** @type {HTMLElement} */ (node).dataset.index)];
    node.setAttribute("aria-pressed", String(!!b && !!applied && b.filter === applied));
  }
}

/** Requests of the expert indicator: a newer load (or a reload) wins. */
let expertSeq = 0;

/** Hide the expert indicator (a capture is (re)loading). */
export function resetExpert() {
  expertSeq++;
  state.expert = null;
  renderExpert();
}

/**
 * Count the capture's expert items for the status bar, once it is completely
 * indexed (the backend refuses before).
 */
export async function loadExpertSummary() {
  resetExpert();
  const seq = expertSeq;
  try {
    const res = await rpc("expert_summary", {}).promise;
    if (seq === expertSeq) {
      state.expert = res.counts;
      renderExpert();
    }
  } catch {
    /* the indicator is optional (cancelled, closed, or tshark failed) */
  }
}

function renderExpert() {
  const counts = state.expert;
  el.statusExpert.classList.toggle("hidden", !counts || !state.info);
  if (!counts) {
    el.statusExpert.replaceChildren();
    return;
  }
  const status = lib.expertStatus(counts);
  const glyph = { error: "error", warning: "warning", note: "info", ok: "pass" }[status.severity];
  const mark = icon(glyph);
  mark.classList.add(`expert-${status.severity}`);
  el.statusExpert.replaceChildren(mark, document.createTextNode(status.label));
  el.statusExpert.title = status.title;
  el.statusExpert.setAttribute("aria-label", status.title);
}

el.statusExpert.addEventListener("click", () =>
  vscode.postMessage({ type: "runCommand", id: "pcapViewer.statistics.expertInfo" }),
);

export function updateStatus() {
  updateFilterButtons();
  renderProgress();
  const info = state.info;
  el.statusTime.textContent = TIME_LABELS[state.timeFormat] ?? "";
  el.statusTime.classList.toggle("hidden", !info);
  el.statusNames.classList.toggle("hidden", !info);
  el.statusLua.classList.toggle("hidden", !info || !el.statusLua.textContent);
  if (!info) {
    el.statusLeft.textContent = "";
    el.statusInfo.textContent = "";
    return;
  }
  const parts = [`Packets: ${info.frames.toLocaleString()}`];
  if (state.indexing && !state.capture) {
    parts[0] = lib.indexingLabel({
      phase: state.indexPhase,
      frames: info.frames,
      fraction: state.indexFraction,
      resumedAt: state.resumedAt,
    });
  }
  if (state.filtering) {
    const pct =
      state.filterFraction !== null ? ` (${Math.round(state.filterFraction * 100)}%)` : "";
    parts.push(`Filtering… ${state.matchCount.toLocaleString()} matches so far${pct}`);
  } else if (state.appliedFilter) {
    const pct = info.frames ? ((state.matchCount / info.frames) * 100).toFixed(1) : "0";
    const stopped = state.filterPartial ? ", filter stopped early" : "";
    parts.push(`Displayed: ${state.matchCount.toLocaleString()} (${pct}%${stopped})`);
  }
  if (state.selectedFrame !== null) {
    const multi = state.selection.size ? ` (${state.selection.size.toLocaleString()} packets)` : "";
    parts.push(`Selected: ${state.selectedFrame}${multi}`);
  }
  if (state.markCount) {
    parts.push(`Marked: ${state.markCount.toLocaleString()}`);
  }
  if (state.coloringProgress !== undefined) {
    const pct =
      state.coloringProgress !== null ? ` ${Math.round(state.coloringProgress * 100)}%` : "";
    parts.push(`Coloring…${pct}`);
  }
  if (state.exportProgress !== undefined) {
    const pct = state.exportProgress !== null ? ` ${Math.round(state.exportProgress * 100)}%` : "";
    parts.push(`Exporting…${pct}`);
  }
  if (state.timeRef !== null) {
    parts.push(`Time reference: ${state.timeRef}`);
  }
  el.statusLeft.textContent = parts.join(" · ");
  const right = [info.fileType, info.linkType, lib.formatBytes(info.size)].filter(Boolean);
  if (typeof state.elapsedMs === "number") {
    right.push(`loaded in ${(state.elapsedMs / 1000).toFixed(1)} s`);
  }
  el.statusInfo.textContent = right.join(" · ");
}

export function persist() {
  const root = document.documentElement.style;
  vscode.setState({
    widths: state.widths,
    expanded: [...state.expanded].slice(-200),
    menuGroups: [...state.menuGroups],
    detailView: state.detailView,
    diagramValues: state.diagramValues,
    listHeight: root.getPropertyValue("--list-height"),
    treeWidth: root.getPropertyValue("--tree-width"),
  });
}
