// @ts-check
/**
 * The keyboard shortcuts overlay (`?`, or "PCAP: Keyboard Shortcuts"): a
 * modal dialog listing the viewer's own keys and every command's key
 * binding (lib.shortcutSections), as the platform shows them.
 */

import { el, isMac, lib, state } from "./core.js";

/** Where the focus was before the dialog opened (it goes back there). @type {HTMLElement | null} */
let returnFocus = null;

export function openShortcuts() {
  const frag = document.createDocumentFragment();
  for (const section of lib.shortcutSections(state.commands, isMac)) {
    const table = document.createElement("table");
    const caption = document.createElement("caption");
    caption.textContent = section.area;
    const body = document.createElement("tbody");
    for (const [keys, action] of section.keys) {
      const row = document.createElement("tr");
      const keyCell = document.createElement("td");
      const kbd = document.createElement("kbd");
      kbd.textContent = keys;
      keyCell.append(kbd);
      const actionCell = document.createElement("td");
      actionCell.textContent = action;
      row.append(keyCell, actionCell);
      body.append(row);
    }
    table.append(caption, body);
    frag.append(table);
  }
  el.shortcutsBody.replaceChildren(frag);
  returnFocus = /** @type {HTMLElement | null} */ (document.activeElement);
  el.shortcuts.classList.remove("hidden");
  el.shortcutsBody.scrollTop = 0;
  el.shortcutsClose.focus();
}

function closeShortcuts() {
  el.shortcuts.classList.add("hidden");
  (returnFocus ?? el.viewport).focus();
  returnFocus = null;
}

el.shortcutsClose.addEventListener("click", closeShortcuts);
// A click outside the box closes it.
el.shortcuts.addEventListener("click", (e) => {
  if (e.target === el.shortcuts) {
    closeShortcuts();
  }
});
el.shortcuts.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    closeShortcuts();
  } else if (e.key === "Tab") {
    // Keep the focus inside the dialog: the close button and the list.
    e.preventDefault();
    (document.activeElement === el.shortcutsClose ? el.shortcutsBody : el.shortcutsClose).focus();
  }
});
document.addEventListener("keydown", (e) => {
  const t = /** @type {HTMLElement} */ (e.target);
  const typing =
    t.tagName === "INPUT" ||
    t.tagName === "TEXTAREA" ||
    t.tagName === "SELECT" ||
    t.isContentEditable;
  if (e.key === "?" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
    if (el.shortcuts.classList.contains("hidden")) {
      e.preventDefault();
      openShortcuts();
    }
  }
});
