// @ts-check
/**
 * What the panels share (a classic script: exposes `window.PcapPanel`):
 * Codicons, buttons with an icon before their label, and row menus for their
 * tables and lists on top of menus.js (right-click, Shift+F10 or the menu
 * key on the selected row).
 */
(function () {
  "use strict";

  /** A Codicons glyph (codicons/codicon.css), hidden from screen readers. @param {string} name */
  function icon(name) {
    const span = document.createElement("span");
    span.className = `codicon codicon-${name}`;
    span.setAttribute("aria-hidden", "true");
    return span;
  }

  /**
   * Put a Codicon before a button's label (its text stays its name).
   * @template {HTMLElement} T @param {T} button @param {string} name @returns {T}
   */
  function withIcon(button, name) {
    button.classList.add("with-icon");
    button.prepend(icon(name));
    return button;
  }

  /**
   * Shift+F10 and the menu key: Chromium turns them into "contextmenu" on
   * Windows and Linux but not on macOS, so they're handled here, and the
   * "contextmenu" that may follow them is ignored.
   */
  let keyMenuAt = -Infinity;

  /**
   * A menu for the rows of a table or list: right-click a row (it is selected
   * first), or Shift+F10 / the menu key while the focus is inside `container`
   * (the selected row's menu, below it).
   * @param {HTMLElement} container
   * @param {object} spec
   * @param {string} spec.rows a selector for the rows inside `container`
   * @param {string} [spec.selected] a selector for the selected row ("<rows>.selected")
   * @param {(row: HTMLElement) => void} spec.select selects a row (a click on it, say)
   * @param {(row: HTMLElement, cell: HTMLElement | null) => any[] | null} spec.entries
   *   the menu's entries (menus.js), or null for none
   */
  function rowMenu(container, spec) {
    const menus = /** @type {any} */ (window).PcapMenus;
    const selected = spec.selected ?? `${spec.rows}.selected`;
    /**
     * @param {HTMLElement | null} row @param {HTMLElement | null} cell
     * @param {number | null} x @param {number | null} y
     */
    const open = (row, cell, x, y) => {
      if (!row) {
        return false;
      }
      spec.select(row);
      const entries = spec.entries(row, cell);
      if (!entries || !entries.length) {
        return false;
      }
      const rect = row.getBoundingClientRect();
      menus.show(x ?? rect.left + 24, y ?? rect.bottom, entries);
      return true;
    };
    container.addEventListener("contextmenu", (e) => {
      const target = /** @type {HTMLElement} */ (e.target);
      const fromKeys = e.button !== 2;
      if (fromKeys && Date.now() - keyMenuAt < 1000) {
        e.preventDefault(); // (already opened on the key)
        return;
      }
      const row = /** @type {HTMLElement | null} */ (target.closest(spec.rows));
      const pick = row && container.contains(row) ? row : null;
      const opened = fromKeys
        ? open(container.querySelector(selected), null, null, null)
        : open(
            pick,
            /** @type {HTMLElement | null} */ (target.closest("td, th")),
            e.clientX,
            e.clientY,
          );
      if (opened) {
        e.preventDefault();
      }
    });
    container.addEventListener("keydown", (e) => {
      if ((e.key === "F10" && e.shiftKey) || e.key === "ContextMenu") {
        if (open(container.querySelector(selected), null, null, null)) {
          e.preventDefault();
          keyMenuAt = Date.now();
        }
      }
    });
  }

  /** @type {any} */ (window).PcapPanel = { icon, withIcon, rowMenu };
})();
