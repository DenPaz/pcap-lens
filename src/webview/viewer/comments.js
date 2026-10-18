// @ts-check
/** Packet comments (the comment bar and edits), and going to a frame when the view changes. */

import { $, el, rpc, state, vscode } from "./core.js";
import { orderParams, scheduleRender } from "./list.js";
import { scrollIndexIntoView, selectIndex } from "./selection.js";
import { clearDetail } from "./detail.js";
import { applyFilter, showFilterError, showNotice } from "./filterbar.js";
import { recordJump } from "./navigation.js";
import { updateStatus } from "./status.js";

/** Comment shown in the bar: frame, text ("" none), unsaved edit. */
const comment = { frame: /** @type {number | null} */ (null), text: "", edited: false };

/**
 * Show `frame`'s comment above its details (edits included), or hide the bar.
 * @param {number | null} frame
 */
export async function showComment(frame) {
  if (frame === null) {
    comment.frame = null;
    el.commentBar.classList.add("hidden");
    return;
  }
  let res;
  try {
    res = await rpc("packet_comments", { frames: [frame] }).promise;
  } catch {
    return; // (no capture)
  }
  if (state.selectedFrame !== frame) {
    return;
  }
  const editing = !el.commentEditor.classList.contains("hidden") && comment.frame === frame;
  comment.frame = frame;
  comment.text = res.comments[String(frame)] ?? "";
  comment.edited = res.edited.includes(frame);
  el.commentText.textContent = comment.text;
  el.commentEdited.classList.toggle("hidden", !comment.edited);
  if (!editing) {
    el.commentEditor.classList.add("hidden");
    el.commentView.classList.remove("hidden");
    el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
  }
  if (!comment.text && comment.edited) {
    el.commentText.textContent = "(comment deleted)";
  }
}

/** Edit (or add) the selected packet's comment in the bar. */
export function editComment() {
  const frame = state.selectedFrame;
  if (frame === null) {
    return;
  }
  const open = () => {
    el.commentInput.value = comment.frame === frame ? comment.text : "";
    el.commentView.classList.add("hidden");
    el.commentEditor.classList.remove("hidden");
    el.commentBar.classList.remove("hidden");
    el.commentInput.focus();
  };
  if (comment.frame === frame) {
    open();
  } else {
    void showComment(frame).then(open);
  }
}

function applyComment() {
  if (comment.frame === null) {
    return;
  }
  const text = el.commentInput.value.replace(/\s+$/, "");
  el.commentEditor.classList.add("hidden");
  el.commentView.classList.remove("hidden");
  if (text !== comment.text) {
    vscode.postMessage({ type: "setComment", frame: comment.frame, text });
  } else {
    el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
  }
}

function cancelComment() {
  el.commentEditor.classList.add("hidden");
  el.commentView.classList.remove("hidden");
  el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
  el.viewport.focus();
}

/** @param {number} frame */
export function deleteComment(frame) {
  vscode.postMessage({ type: "setComment", frame, text: "" });
}

$("comment-edit").addEventListener("click", () => editComment());
$("comment-delete").addEventListener("click", () => {
  if (comment.frame !== null) {
    deleteComment(comment.frame);
  }
});
$("comment-apply").addEventListener("click", () => applyComment());
$("comment-cancel").addEventListener("click", () => cancelComment());
el.commentInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    applyComment();
  } else if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    cancelComment();
  }
});

/** After a filter/sort change, find where the selected frame went. */
export async function relocateSelection() {
  const frame = state.selectedFrame;
  if (frame === null) {
    return;
  }
  const viewKey = state.viewKey;
  try {
    const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
    if (
      res.filterId !== state.filterId ||
      frame !== state.selectedFrame ||
      viewKey !== state.viewKey
    ) {
      return;
    }
    if ((res.index === null || res.index === undefined) && state.filtering) {
      state.selectedIndex = null; // it may still come: looked up again when the filter is done
    } else if (res.index === null || res.index === undefined) {
      state.selectedIndex = null;
      state.selectedFrame = null;
      clearDetail();
      updateStatus();
    } else {
      state.selectedIndex = res.index;
      scrollIndexIntoView(res.index, true);
    }
    scheduleRender();
  } catch {
    /* ignore */
  }
}

/**
 * Select a frame by number (go to packet, frame links, history). If the
 * filter hides it, say so and offer to clear the filter.
 * @param {number} frame @param {{record?: boolean}} [opts] record: add the jump to the back history
 * @returns {Promise<boolean>}
 */
export async function gotoFrame(frame, opts = {}) {
  if (!state.ready) {
    return false;
  }
  try {
    const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
    if (res.index === null || res.index === undefined) {
      showNotice(
        `Packet ${frame} is not displayed with the current filter.`,
        state.appliedFilter
          ? { label: "Clear filter and go", run: () => void clearFilterAndGo(frame, opts) }
          : undefined,
      );
      return false;
    }
    if (opts.record !== false) {
      recordJump(frame);
    }
    selectIndex(res.index, true);
    el.viewport.focus();
    return true;
  } catch (err) {
    showFilterError(String(/** @type {any} */ (err)?.message ?? err), true);
    return false;
  }
}

/** @param {number} frame @param {{record?: boolean}} opts */
async function clearFilterAndGo(frame, opts) {
  el.filterInput.value = "";
  await applyFilter("");
  await gotoFrame(frame, opts);
}
