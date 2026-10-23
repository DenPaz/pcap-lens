// @ts-check
/**
 * The toolbar under the filter bar: going through the packets (Go to,
 * first, previous, next, last, back, forward), Mark, Find and the coloring
 * switch, as icon buttons with their key bindings in the tooltip. One Tab
 * stop: the arrow keys, Home and End move between the buttons (a roving
 * tabindex). Buttons that can't act now are disabled (updateToolbar, from
 * updateStatus).
 */

import { el, icon, state, vscode } from "./core.js";
import { commandKeys, viewerKeys } from "./menu.js";
import { runCommand } from "./navigation.js";
import { selectIndex } from "./selection.js";

/**
 * @typedef {object} Tool
 * @property {string} id the button's id (tool-<id>)
 * @property {string} label
 * @property {string} icon a Codicon
 * @property {() => string} keys its key binding as shown ("" for none)
 * @property {() => void} run
 * @property {() => boolean} [enabled]
 * @property {() => boolean} [pressed] a toggle button
 */

const hasPackets = () => state.ready && state.total > 0;
const hasSelection = () => hasPackets() && state.selectedIndex !== null;
/** @param {number} step */
const step = (step) => {
  const cur = state.selectedIndex ?? (step > 0 ? -1 : state.total);
  selectIndex(Math.max(0, Math.min(state.total - 1, cur + step)));
  el.viewport.focus({ preventScroll: true });
};
/** A command the host runs (it checks the id against the ☰ list). @param {string} id */
const host = (id) => () => vscode.postMessage({ type: "runCommand", id });

/** @type {(Tool | "-")[]} */
const TOOLS = [
  {
    id: "go-to",
    label: "Go to Packet…",
    icon: "symbol-numeric",
    keys: () => commandKeys("pcapViewer.goToPacket"),
    run: host("pcapViewer.goToPacket"),
    enabled: hasPackets,
  },
  {
    id: "first",
    label: "First Packet",
    icon: "arrow-circle-up",
    keys: () => viewerKeys("ctrl+home"),
    run: () => runCommand("firstPacket"),
    enabled: hasPackets,
  },
  {
    id: "previous",
    label: "Previous Packet",
    icon: "chevron-up",
    keys: () => viewerKeys("up"),
    run: () => step(-1),
    enabled: hasPackets,
  },
  {
    id: "next",
    label: "Next Packet",
    icon: "chevron-down",
    keys: () => viewerKeys("down"),
    run: () => step(1),
    enabled: hasPackets,
  },
  {
    id: "last",
    label: "Last Packet",
    icon: "arrow-circle-down",
    keys: () => viewerKeys("ctrl+end"),
    run: () => runCommand("lastPacket"),
    enabled: hasPackets,
  },
  "-",
  {
    id: "back",
    label: "Back",
    icon: "arrow-left",
    keys: () => commandKeys("pcapViewer.goBack"),
    run: () => runCommand("goBack"),
    enabled: hasPackets,
  },
  {
    id: "forward",
    label: "Forward",
    icon: "arrow-right",
    keys: () => commandKeys("pcapViewer.goForward"),
    run: () => runCommand("goForward"),
    enabled: hasPackets,
  },
  "-",
  {
    id: "mark",
    label: "Mark/Unmark Packet",
    icon: "bookmark",
    keys: () => commandKeys("pcapViewer.toggleMark"),
    run: () => runCommand("toggleMark"),
    enabled: hasSelection,
  },
  {
    id: "find",
    label: "Find Packet…",
    icon: "search",
    keys: () => viewerKeys("ctrl+f"),
    run: () => runCommand("find"),
    enabled: hasPackets,
  },
  {
    id: "coloring",
    label: "Color Packets",
    icon: "symbol-color",
    keys: () => "",
    run: host("pcapViewer.toggleColoring"),
    pressed: () => state.coloring !== null,
  },
];

/** @type {{tool: Tool, node: HTMLButtonElement}[]} */
const buttons = [];

el.navTools.replaceChildren(
  ...TOOLS.map((tool) => {
    if (tool === "-") {
      const sep = document.createElement("span");
      sep.className = "tool-sep";
      sep.setAttribute("role", "separator");
      sep.setAttribute("aria-orientation", "vertical");
      return sep;
    }
    const node = document.createElement("button");
    node.type = "button";
    node.id = `tool-${tool.id}`;
    node.className = "icon";
    node.tabIndex = buttons.length ? -1 : 0;
    node.setAttribute("aria-label", tool.label);
    if (tool.pressed) {
      node.setAttribute("aria-pressed", "false");
    }
    node.append(icon(tool.icon));
    node.addEventListener("click", () => tool.run());
    node.addEventListener("focus", () => {
      for (const b of buttons) {
        b.node.tabIndex = b.node === node ? 0 : -1;
      }
    });
    buttons.push({ tool, node });
    return node;
  }),
);

el.navTools.addEventListener("keydown", (e) => {
  const at = buttons.findIndex((b) => b.node === document.activeElement);
  /** @type {Record<string, number>} */
  const moves = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: buttons.length - 1 };
  if (at < 0 || !(e.key in moves)) {
    return;
  }
  e.preventDefault();
  e.stopPropagation();
  const n = buttons.length;
  buttons[(moves[e.key] + n) % n].node.focus();
});

/** Enable, press and title the buttons for the current state. */
export function updateToolbar() {
  for (const { tool, node } of buttons) {
    // (aria-disabled, not disabled: a disabled button would lose the focus.)
    const off = tool.enabled ? !tool.enabled() : false;
    node.setAttribute("aria-disabled", String(off));
    node.classList.toggle("disabled", off);
    if (tool.pressed) {
      node.setAttribute("aria-pressed", String(tool.pressed()));
    }
    const keys = tool.keys();
    node.title = keys ? `${tool.label} (${keys})` : tool.label;
  }
}

// A click on a disabled button does nothing.
el.navTools.addEventListener(
  "click",
  (e) => {
    const node = /** @type {HTMLElement} */ (e.target).closest("button");
    if (node?.getAttribute("aria-disabled") === "true") {
      e.stopImmediatePropagation();
    }
  },
  true,
);
updateToolbar();
