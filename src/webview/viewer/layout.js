// @ts-check
/** The splitters between the list, tree and bytes panes. */

import { $, el } from "./core.js";
import { persist } from "./status.js";

/**
 * @param {HTMLElement} handle
 * @param {"row" | "col"} axis
 */
function makeSplitter(handle, axis) {
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
      const pct = `${Math.round(Math.max(0.1, Math.min(0.9, ratio)) * 1000) / 10}%`;
      document.documentElement.style.setProperty(
        axis === "row" ? "--list-height" : "--tree-width",
        pct,
      );
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
