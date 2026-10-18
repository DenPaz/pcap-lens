// @ts-check
/** The loading / error overlay. */

import { el, state, vscode } from "./core.js";
import { setProgress } from "./host.js";

/**
 * @param {string} message
 * @param {{progress?: boolean, error?: boolean, reload?: boolean}} opts
 */
export function showOverlay(message, opts) {
  el.overlay.classList.remove("hidden");
  el.overlayBox.classList.toggle("error", !!opts.error);
  el.overlayMessage.textContent = message;
  el.overlayProgress.classList.toggle("hidden", !opts.progress);
  if (opts.progress) {
    setProgress(el.overlayProgress, el.overlayFill, null);
  }
  el.overlayDetail.textContent = "";
  el.overlayCancel.classList.toggle("hidden", !opts.progress);
  el.overlayReload.classList.toggle("hidden", !opts.reload);
  el.overlayLog.classList.toggle("hidden", !opts.error);
  if (opts.error) {
    state.ready = false;
  }
}

export function hideOverlay() {
  el.overlay.classList.add("hidden");
}

el.overlayCancel.addEventListener("click", () => vscode.postMessage({ type: "cancelLoad" }));
el.overlayReload.addEventListener("click", () => vscode.postMessage({ type: "reload" }));
el.overlayLog.addEventListener("click", () => vscode.postMessage({ type: "showLog" }));
