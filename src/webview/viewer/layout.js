// @ts-check
/**
 * The panes: where they go (pcapViewer.paneLayout, pcapViewer.showBytesPane)
 * and the splitters between them. A splitter's direction follows the layout:
 * its aria-orientation says which way it lies, and its keys and drags follow.
 */

import { el, lib, saved, state, vscode } from "./core.js";
import { showMenu } from "./menu.js";
import { persist } from "./status.js";

/** The pane size a splitter sets: a CSS variable in percent (10–90), and its default. */
const SPLITS = {
  list: { variable: "--list-size", saved: "listHeight", initial: 50 },
  detail: { variable: "--detail-size", saved: "treeWidth", initial: 55 },
};

/** The splitter after the list and the one between details and bytes. */
const HANDLES = { list: el.splitH, detail: el.splitV };

/** The layouts as the menu shows them. */
const LAYOUT_LABELS = {
  below: "Details and Bytes Below the List",
  stacked: "List, Details and Bytes Stacked",
  beside: "Details and Bytes Beside the List",
};

/**
 * Size the list or the details to `pct` percent, and tell assistive
 * technology (the separator's aria-valuenow).
 * @param {"list" | "detail"} which
 * @param {number} pct
 */
function setSplit(which, pct) {
  const value = Math.round(Math.max(10, Math.min(90, pct)) * 10) / 10;
  document.documentElement.style.setProperty(SPLITS[which].variable, `${value}%`);
  HANDLES[which].setAttribute("aria-valuenow", String(value));
}

/** @param {HTMLElement} handle */
const isVertical = (handle) => handle.getAttribute("aria-orientation") === "vertical";

/**
 * Drag, or focus and use the arrow keys (Home/End for the extremes).
 * @param {"list" | "detail"} which
 */
function makeSplitter(which) {
  const handle = HANDLES[which];
  const initial = saved[SPLITS[which].saved] ?? `${SPLITS[which].initial}%`;
  document.documentElement.style.setProperty(SPLITS[which].variable, initial);
  handle.setAttribute("aria-valuenow", String(parseFloat(initial) || SPLITS[which].initial));
  handle.addEventListener("keydown", (e) => {
    const now = Number(handle.getAttribute("aria-valuenow"));
    const less = isVertical(handle) ? "ArrowLeft" : "ArrowUp";
    const more = isVertical(handle) ? "ArrowRight" : "ArrowDown";
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
    setSplit(which, next);
    persist();
  });
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    handle.classList.add("dragging");
    const container = which === "list" ? el.main : el.bottom;
    const vertical = isVertical(handle);
    /** @param {MouseEvent} ev */
    const move = (ev) => {
      const rect = container.getBoundingClientRect();
      const ratio = vertical
        ? (ev.clientX - rect.left) / rect.width
        : (ev.clientY - rect.top) / rect.height;
      setSplit(which, ratio * 100);
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

/**
 * Put the panes where `layout` says, with or without the bytes pane.
 * @param {unknown} layout
 * @param {boolean} bytes
 * @param {boolean} [remember] keep it in the webview state (the next load starts with it)
 */
export function applyPaneLayout(layout, bytes, remember = true) {
  state.paneLayout = lib.paneLayout(layout);
  state.bytesPane = bytes;
  el.main.dataset.layout = state.paneLayout;
  el.main.classList.toggle("no-bytes", !bytes);
  el.bytes.classList.toggle("hidden", !bytes);
  el.splitV.classList.toggle("hidden", !bytes);
  const orientations = lib.splitterOrientations(state.paneLayout);
  for (const which of /** @type {const} */ (["list", "detail"])) {
    const handle = HANDLES[which];
    const vertical = orientations[which] === "vertical";
    handle.setAttribute("aria-orientation", orientations[which]);
    handle.classList.toggle("vertical", vertical);
    handle.classList.toggle("horizontal", !vertical);
  }
  if (remember) {
    persist();
  }
}

/**
 * Ask the host to change the settings (it writes them, and every viewer
 * gets the new layout back as a "paneLayout" message).
 * @param {{layout?: string, bytes?: boolean}} change
 */
function changeLayout(change) {
  vscode.postMessage({ type: "setPaneLayout", ...change });
}

/** The layout menu's entries. @returns {import("./menu.js").MenuEntry[]} */
export function layoutMenuEntries() {
  return [
    ...lib.PANE_LAYOUTS.map((/** @type {"below" | "stacked" | "beside"} */ layout) => ({
      label: LAYOUT_LABELS[layout],
      checked: state.paneLayout === layout,
      radio: true,
      action: () => changeLayout({ layout }),
    })),
    "-",
    {
      label: "Show Packet Bytes",
      checked: state.bytesPane,
      action: () => changeLayout({ bytes: !state.bytesPane }),
    },
    "-",
    {
      label: "Reset Pane Sizes",
      icon: "discard",
      action: () => {
        setSplit("list", SPLITS.list.initial);
        setSplit("detail", SPLITS.detail.initial);
        persist();
      },
    },
  ];
}

/** Open the layout menu under `button`. @param {HTMLElement} button */
export function showLayoutMenu(button) {
  const rect = button.getBoundingClientRect();
  showMenu(rect.left, rect.bottom, layoutMenuEntries());
}

makeSplitter("list");
makeSplitter("detail");
applyPaneLayout(state.paneLayout, state.bytesPane, false);
