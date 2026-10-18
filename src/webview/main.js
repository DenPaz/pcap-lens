// @ts-check
/**
 * PCAP Lens webview: filter bar, virtualized packet list, detail tree and
 * hex view. Talks to the extension host with postMessage; the host forwards
 * whitelisted calls to the Python backend.
 *
 * The capture editor's entry module: it imports the viewer's modules
 * (viewer/*.js, one per part of the UI; viewer/core.js holds the shared
 * state and imports nothing) and starts the page.
 *
 * Security: packet data is untrusted. It is only ever inserted with
 * textContent / createElement — never innerHTML.
 */
import { saved, state, vscode } from "./viewer/core.js";
import "./viewer/host.js";
import { showOverlay } from "./viewer/overlay.js";
import "./viewer/columns.js";
import "./viewer/list.js";
import "./viewer/selection.js";
import "./viewer/comments.js";
import "./viewer/detail.js";
import "./viewer/diagram.js";
import "./viewer/contextmenu.js";
import "./viewer/commandmenu.js";
import "./viewer/filterbar.js";
import "./viewer/autocomplete.js";
import "./viewer/navigation.js";
import "./viewer/header.js";
import "./viewer/ai.js";
import "./viewer/layout.js";
import "./viewer/status.js";

if (saved.listHeight) {
  document.documentElement.style.setProperty("--list-height", saved.listHeight);
}
if (saved.treeWidth) {
  document.documentElement.style.setProperty("--tree-width", saved.treeWidth);
}
const rh = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--row-height"));
if (rh > 0) {
  state.rowHeight = rh;
}
showOverlay("Starting…", { progress: true });
vscode.postMessage({ type: "ready" });
