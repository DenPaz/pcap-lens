// @ts-check
/**
 * The packet list's overview strip, beside its scrollbar (Wireshark's
 * "intelligent scroll bar"): the whole view (filter and sort order) squeezed
 * into the strip's height. Each pixel row shows the coloring rule most of its
 * packets have, and lanes on the right mark slices with marked, commented and
 * (while the find bar is open) found packets; a box shows the rows on screen.
 * A click or drag scrolls there. The backend's `view_overview` does the
 * counting, so it covers every row, not only the pages loaded.
 */

import { cancelRpc, el, lib, rpc, state } from "./core.js";
import { orderParams, scheduleRender } from "./list.js";

/** @type {{rows: number, colors: number[], flags: number[], coloringId: number, filterId: number} | null} */
let data = null;
let wantedKey = "";
let loadedKey = "";
let timer = 0;
/** @type {number | null} */
let request = null;

/** Flag bits of a slice (backend OVERVIEW_*). */
const MARKED = 1;
const COMMENT = 2;
const FOUND = 4;

/** What the strip shows depends on these; a change means asking the backend again. */
function overviewKey() {
  return [
    state.filterId,
    state.sort ? `${state.sort.field}:${state.sort.desc}` : "",
    state.timeFormat,
    state.total,
    state.coloring?.id ?? 0,
    state.markCount,
    state.ignoredCount,
    state.rowsVersion,
    findShown() ? state.findVersion : "",
    el.overview.clientHeight,
  ].join("|");
}

/** The latest Find Packet's matches are drawn while the find bar is open. */
function findShown() {
  return !el.findBar.classList.contains("hidden") && state.findVersion > 0;
}

/**
 * Redraw the strip, and ask the backend for new counts when what they depend
 * on changed (debounced; less often while a capture or filter is still being
 * read, since every request walks the whole view).
 */
export function scheduleOverview() {
  drawOverview();
  const key = overviewKey();
  if (key === wantedKey) {
    return;
  }
  wantedKey = key;
  window.clearTimeout(timer);
  timer = window.setTimeout(loadOverview, state.indexing || state.filtering ? 3000 : 200);
}

async function loadOverview() {
  const height = el.overview.clientHeight;
  if (!state.ready || !state.total || !height) {
    data = null;
    drawOverview();
    return;
  }
  const key = wantedKey;
  if (key === loadedKey) {
    return;
  }
  if (request !== null) {
    cancelRpc(request);
  }
  const req = rpc("view_overview", { buckets: height, find: findShown(), ...orderParams() });
  request = req.id;
  try {
    const res = await req.promise;
    if (res.filterId === state.filterId) {
      data = res;
      loadedKey = key;
      drawOverview();
    }
  } catch {
    // (Cancelled by a newer request, or the capture went away: keep the last drawing.)
  } finally {
    if (request === req.id) {
      request = null;
    }
  }
}

/** Draw the strip from the last counts and the rows on screen. */
export function drawOverview() {
  const canvas = el.overview;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  canvas.classList.toggle("hidden", !state.ready || !state.total);
  if (!width || !height) {
    return;
  }
  const ratio = window.devicePixelRatio || 1;
  if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
  }
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const css = getComputedStyle(canvas);
  const color = (/** @type {string} */ name) => css.getPropertyValue(name).trim();
  const lane = 3; // px per flag lane, on the right
  const colorsWidth = Math.max(2, width - 3 * lane);
  if (data && data.rows === state.total && data.colors.length) {
    const theme = lib.themeKind(document.body.classList);
    const rules =
      data.coloringId && data.coloringId === state.coloring?.id ? state.coloring.rules : [];
    /** @type {Map<number, string>} */
    const stripes = new Map();
    const n = data.colors.length;
    for (let b = 0; b < n; b++) {
      const y = (b * height) / n;
      const h = Math.max(1, height / n);
      const rule = rules[data.colors[b] - 1];
      if (rule) {
        if (!stripes.has(data.colors[b])) {
          stripes.set(data.colors[b], lib.ruleStyle(rule, theme, "stripe").stripe);
        }
        ctx.fillStyle = /** @type {string} */ (stripes.get(data.colors[b]));
        ctx.fillRect(0, y, colorsWidth, h);
      }
      const flags = data.flags[b];
      if (flags) {
        const marks = [
          [COMMENT, "--overview-comment"],
          [MARKED, "--overview-mark"],
          [FOUND, "--overview-found"],
        ];
        marks.forEach(([bit, name], i) => {
          if (flags & /** @type {number} */ (bit)) {
            ctx.fillStyle = color(/** @type {string} */ (name));
            ctx.fillRect(colorsWidth + i * lane, y, lane, Math.max(2, h));
          }
        });
      }
    }
  }
  // The rows on screen.
  const win = lib.computeWindow({
    scrollTop: el.viewport.scrollTop,
    viewportHeight: el.viewport.clientHeight,
    total: state.total,
    rowHeight: state.rowHeight,
  });
  const box = lib.overviewBox(win.first, win.count, state.total, height);
  if (box) {
    ctx.fillStyle = color("--overview-window");
    ctx.fillRect(0, box.y, width, box.h);
  }
}

/** Scroll so the row under `clientY` is in the middle of the list. @param {number} clientY */
function scrollToPoint(clientY) {
  const rect = el.overview.getBoundingClientRect();
  const index = lib.overviewIndexAt(clientY - rect.top, rect.height, state.total);
  if (index === null) {
    return;
  }
  el.viewport.scrollTop = lib.scrollTopForIndex({
    index,
    scrollTop: el.viewport.scrollTop,
    viewportHeight: el.viewport.clientHeight,
    total: state.total,
    rowHeight: state.rowHeight,
    center: true,
  });
  scheduleRender();
}

el.overview.addEventListener("pointerdown", (e) => {
  if (e.button !== 0) {
    return;
  }
  e.preventDefault();
  el.overview.setPointerCapture(e.pointerId);
  scrollToPoint(e.clientY);
});
el.overview.addEventListener("pointermove", (e) => {
  if (el.overview.hasPointerCapture(e.pointerId)) {
    scrollToPoint(e.clientY);
  }
});
