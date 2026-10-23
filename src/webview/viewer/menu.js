// @ts-check
/**
 * The viewer's context menus: the shared engine (menus.js, `window.PcapMenus`)
 * plus the key bindings shown in them.
 */

import { isMac, lib, state } from "./core.js";

/**
 * @typedef {object} MenuItem
 * @property {string} label
 * @property {string} [icon] a Codicon name
 * @property {string} [hint] dimmed text after the label (truncated)
 * @property {string} [keys] a key binding as shown ("Ctrl+M")
 * @property {(() => void) | null} [action] null: disabled
 * @property {boolean} [checked] a checkbox item
 * @property {MenuEntry[] | (() => Promise<MenuEntry[]>)} [children]
 * @property {string} [title] tooltip
 */
/** @typedef {MenuItem | "-"} MenuEntry */
/** The older form: [label, action (null: disabled), checked?]; "-" a separator. */
/** @typedef {[string, (() => void) | null, boolean?]} MenuTuple */

const engine = /** @type {any} */ (window).PcapMenus;

/**
 * The key binding of a contributed command as the platform shows it ("" if
 * none), from the ☰ list the host sent.
 * @param {string} id
 */
export function commandKeys(id) {
  const command = state.commands.find((/** @type {any} */ c) => c.id === id);
  return command ? lib.formatKeybinding(command.keys, isMac) : "";
}

/** A key the webview handles itself ("ctrl+a"), as the platform shows it. @param {string} key */
export function viewerKeys(key) {
  return lib.formatKeybinding({ key }, isMac);
}

/**
 * Open a menu at (x, y) (viewport coordinates; it stays inside the window).
 * @param {number} x @param {number} y @param {(MenuEntry | MenuTuple)[]} entries
 */
export function showMenu(x, y, entries) {
  engine.show(x, y, entries);
}

/** Close every menu (and give the focus back when `restore`). @param {boolean} [restore] */
export function hideMenu(restore = false) {
  engine.hide(restore);
}

/** Whether a menu is open. */
export const menuOpen = () => engine.isOpen();
