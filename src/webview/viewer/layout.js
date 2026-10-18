// @ts-check
/** The splitters between the list, tree and bytes panes. */

import { $, el, saved } from "./core.js";
import { persist } from "./status.js";

/** The pane size a splitter sets: a CSS variable in percent (10–90). */
const SPLITS = {
  row: { variable: "--list-height", saved: "listHeight" },
  col: { variable: "--tree-width", saved: "treeWidth" },
};

/**
 * Size the list (row) or the detail tree (col) to `pct` percent, and tell
 * assistive technology (the separator's aria-valuenow).
 * @param {HTMLElement} handle
 * @param {"row" | "col"} axis
 * @param {number} pct
 */
function setSplit(handle, axis, pct) {
  const value = Math.round(Math.max(10, Math.min(90, pct)) * 10) / 10;
  document.documentElement.style.setProperty(SPLITS[axis].variable, `${value}%`);
  handle.setAttribute("aria-valuenow", String(value));
}

/**
 * Drag, or focus and use the arrow keys (Home/End for the extremes).
 * @param {HTMLElement} handle
 * @param {"row" | "col"} axis
 */
function makeSplitter(handle, axis) {
  // (main.js applies the saved size; the CSS default otherwise)
  const initial =
    saved[SPLITS[axis].saved] ??
    getComputedStyle(document.documentElement).getPropertyValue(SPLITS[axis].variable);
  handle.setAttribute("aria-valuenow", String(parseFloat(initial) || 50));
  handle.addEventListener("keydown", (e) => {
    const now = Number(handle.getAttribute("aria-valuenow"));
    const less = axis === "row" ? "ArrowUp" : "ArrowLeft";
    const more = axis === "row" ? "ArrowDown" : "ArrowRight";
    const next =
      e.key === less
        ? now - 2
        : e.key === more
          ? now + 2
          : e.key === "Home"
            ? 10
            : e.key === "End"
              ? 90
              : null;
    if (next === null) {
      return;
    }
    e.preventDefault();
    setSplit(handle, axis, next);
    persist();
  });
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    handle.classList.add("dragging");
    const container =
      axis === "row"
        ? /** @type {HTMLElement} */ ($("main"))
        : /** @type {HTMLElement} */ ($("bottom"));
    /** @param {MouseEvent} ev */
    const move = (ev) => {
      const rect = container.getBoundingClientRect();
      const ratio =
        axis === "row"
          ? (ev.clientY - rect.top) / rect.height
          : (ev.clientX - rect.left) / rect.width;
      setSplit(handle, axis, ratio * 100);
    };
    const up = () => {
      handle.classList.remove("dragging");
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      persist();
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  });
}
makeSplitter(el.splitH, "row");
makeSplitter(el.splitV, "col");
