// @ts-check
/**
 * Shared state, constants, element lookups and the rpc bridge to the host.
 * Imports nothing, so it is evaluated first.
 */

export const vscode = acquireVsCodeApi();
/** @type {any} */
export const lib = /** @type {any} */ (window).PcapLib;

export const PAGE_SIZE = 200;
const MAX_CACHED_PAGES = 100;
export const MAX_INFLIGHT_PAGES = 6;
// Multi-selection limits (the backend's MAX_SELECTION and MAX_PAGE).
export const MAX_SELECTION = 1_000_000;
export const MAX_COPY_ROWS = 100_000;
export const COPY_CHUNK = 5000;

/** @type {Record<string, string>} */
export const TIME_LABELS = {
  relative: "Time: seconds since start",
  delta_displayed: "Time: since previous displayed",
  delta_captured: "Time: since previous captured",
  absolute: "Time: local date and time",
  utc: "Time: UTC date and time",
  epoch: "Time: epoch seconds",
};
export const DEFAULT_WIDTHS = {
  number: 70,
  time: 100,
  source: 150,
  destination: 150,
  protocol: 80,
  length: 64,
};
export const CUSTOM_WIDTH = 120;
export const NUMERIC_IDS = new Set(["number", "time", "length"]);

/** @param {string} id */
export const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

/** A Codicons glyph (codicons/codicon.css), hidden from screen readers. @param {string} name */
export const icon = (name) => {
  const span = document.createElement("span");
  span.className = `codicon codicon-${name}`;
  span.setAttribute("aria-hidden", "true");
  return span;
};

/**
 * The progress bar between the filter bar and the packet list, for the
 * long-running work (lib.progressView: indexing, a streaming filter, an
 * export, coloring, other requests). Built with createElement, styled in
 * styles.css; renderProgress() updates it.
 */
function createProgressBar() {
  const bar = document.createElement("div");
  bar.id = "busy-bar";
  bar.className = "progress-bar hidden";
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  const fill = document.createElement("div");
  fill.className = "progress-fill";
  bar.append(fill);
  $("main").before(bar);
  return { bar, fill };
}
const progressBar = createProgressBar();

export const el = {
  filterInput: /** @type {HTMLInputElement} */ ($("filter-input")),
  filterApply: $("filter-apply"),
  filterClear: $("filter-clear"),
  filterCancel: $("filter-cancel"),
  filterError: $("filter-error"),
  filterSaved: $("filter-saved"),
  filterMenu: $("filter-menu"),
  filterButtons: $("filter-buttons"),
  filterAi: $("filter-ai"),
  filterField: $("filter-field"),
  suggest: $("suggest"),
  busyBar: progressBar.bar,
  busyFill: progressBar.fill,
  list: $("list"),
  header: $("list-header"),
  viewport: $("list-viewport"),
  spacer: $("list-spacer"),
  rows: $("list-rows"),
  empty: $("list-empty"),
  splitH: $("split-h"),
  splitV: $("split-v"),
  detail: $("detail"),
  tree: $("detail-tree"),
  treePlaceholder: $("detail-placeholder"),
  detailPane: $("detail"),
  detailNote: $("detail-note"),
  detailViews: $("detail-views"),
  viewTree: $("view-tree"),
  viewDiagram: $("view-diagram"),
  diagramValues: $("diagram-values"),
  diagram: $("detail-diagram"),
  commentBar: $("comment-bar"),
  commentView: $("comment-view"),
  commentText: $("comment-text"),
  commentEdited: $("comment-edited"),
  commentEditor: $("comment-editor"),
  commentInput: /** @type {HTMLTextAreaElement} */ ($("comment-input")),
  bytesTabs: $("bytes-tabs"),
  bytesView: $("bytes-view"),
  overview: /** @type {HTMLCanvasElement} */ ($("list-overview")),
  shortcuts: $("shortcuts"),
  shortcutsBody: $("shortcuts-body"),
  shortcutsClose: $("shortcuts-close"),
  statusLeft: $("status-left"),
  statusField: $("status-field"),
  statusRight: $("status-right"),
  statusTime: $("status-time"),
  statusNames: $("status-names"),
  statusLua: $("status-lua"),
  statusExpert: $("status-expert"),
  statusInfo: $("status-info"),
  statusCapture: $("status-capture"),
  captureText: $("capture-text"),
  captureStop: $("capture-stop"),
  findBar: $("find-bar"),
  findMode: /** @type {HTMLSelectElement} */ ($("find-mode")),
  findIn: /** @type {HTMLSelectElement} */ ($("find-in")),
  findInput: /** @type {HTMLInputElement} */ ($("find-input")),
  findCase: /** @type {HTMLInputElement} */ ($("find-case")),
  findCaseLabel: $("find-case-label"),
  findPrev: $("find-prev"),
  findNext: $("find-next"),
  findStatus: $("find-status"),
  findClose: $("find-close"),
  overlay: $("overlay"),
  overlayBox: /** @type {HTMLElement} */ (document.querySelector(".overlay-box")),
  overlayMessage: $("overlay-message"),
  overlayProgress: $("overlay-progress"),
  overlayFill: $("overlay-progress-fill"),
  overlayDetail: $("overlay-detail"),
  overlayCancel: $("overlay-cancel"),
  overlayReload: $("overlay-reload"),
  overlayLog: $("overlay-log"),
  menu: $("context-menu"),
};

export const saved = vscode.getState() || {};

export const state = {
  ready: false,
  /** @type {any} */ info: null,
  /** @type {Column[]} */ baseColumns: [],
  /** @type {{field: string, title: string}[]} */ customColumns: [],
  /** @type {Record<string, number>} */ widths: saved.widths || {},
  appliedFilter: "",
  filterId: 0,
  total: 0,
  matchCount: 0,
  /** @type {{field: string, desc: boolean} | null} */ sort: null,
  viewKey: "",
  pages: new lib.LruMap(MAX_CACHED_PAGES),
  /** @type {Map<string, number>} page key -> rpc id */ inflightPages: new Map(),
  /** @type {number | null} */ selectedFrame: null,
  /** @type {number | null} */ selectedIndex: null,
  /** Every selected frame of a multi-selection (Shift/Ctrl+click, Ctrl+A); empty for one. */
  /** @type {Set<number>} */ selection: new Set(),
  /** Row a Shift+click range starts from; the filter the selection was made under. */
  /** @type {number | null} */ anchorIndex: null,
  selectionFilterId: 0,
  rangeSeq: 0,
  /** @type {any} */ detail: null,
  /**
   * The last Find Packet hit of a search in the packet details: its field is
   * selected once that packet's details are shown.
   * @type {{frame: number, value: string, regex: boolean, caseSensitive: boolean} | null}
   */
  findMatch: null,
  /** @type {number | null} */ detailRequest: null,
  /** @type {number | null} */ selectedNodeId: null,
  /** @type {Set<string>} */ expanded: new Set(saved.expanded || []),
  /** The details pane shows the tree or the packet diagram (viewer/diagram.js). */
  /** @type {"tree" | "diagram"} */ detailView: saved.detailView === "diagram" ? "diagram" : "tree",
  /** Packets the selected one refers to, and how (lib.relatedFrames). */
  /** @type {Map<number, string>} */ related: new Map(),
  /** Expert items per severity (expert_summary), once the capture is indexed. */
  /** @type {Record<string, number> | null} */ expert: null,
  /** The diagram's cells show the fields' values too. */
  diagramValues: saved.diagramValues === true,
  activeSource: 0,
  rowHeight: 22,
  /** @type {string[]} */ history: [],
  /** @type {{name: string, filter: string}[]} */ savedFilters: [],
  /** `pcapViewer.filterButtons`: the bar under the filter bar. */
  /** @type {{label: string, filter: string, comment?: string}[]} */ filterButtons: [],
  /** @type {number | null} */ filterRequest: null,
  validateSeq: 0,
  /** @type {number | null} */ elapsedMs: null,
  /** Palette for rows whose list_packets result had this coloringId. */
  /** @type {{id: number, rules: ColorRule[]} | null} */ coloring: null,
  /** How many conversations are colorized (Colorize Conversation's rules, first in `coloring`). */
  colorized: 0,
  /** How rules are drawn (pcapViewer.coloringStyle): auto, full, subtle or stripe. */
  coloringStyle: "auto",
  /** A separate coloring pass is running (fraction, or null when unknown); undefined when not. */
  /** @type {number | null | undefined} */ coloringProgress: undefined,
  /** Column order / hidden columns (pcapViewer.columnLayout). */
  /** @type {{order: string[], hidden: string[]}} */ layout: { order: [], hidden: [] },
  /** Time column format (pcapViewer.timeFormat) and time reference frame (Ctrl+T). */
  timeFormat: "relative",
  /** Quick (approximate) detail from frame `after` on (0 = never), dissecting `window` packets
   * (pcapViewer.quickDetail); two-pass details up to `twoPass` packets (pcapViewer.twoPassDetail). */
  quickDetail: { after: 20000, window: 300, twoPass: 10000 },
  /** @type {number | null} */ quickRequest: null,
  /** Streaming open: the index pass still runs (rows keep arriving; sorting waits). */
  indexing: false,
  /**
   * A live capture writing this file: its interfaces, whether it still runs,
   * and its latest statistics (``seconds`` since ``startedAt``, epoch seconds).
   * @type {{running: boolean, interfaces: string[], filter: string, startedAt: number, packets: number, bytes: number, seconds: number, dropped: number | null} | null}
   */
  capture: null,
  /** @type {number | null} */ indexFraction: null,
  /** "catching-up" while a resumed open re-reads the rows it already shows, else "indexing". */
  indexPhase: "indexing",
  /** Rows a resumed open started with (shown at once), else null. */
  /** @type {number | null} */ resumedAt: null,
  /** An export's progress (undefined: none running, null: amount unknown). */
  /** @type {number | null | undefined} */ exportProgress: undefined,
  /** Streaming filter: its matches are still arriving (a sort applies when it's done). */
  filtering: false,
  /** @type {number | null} */ filterFraction: null,
  /** The filter was stopped (or failed) early: the list holds the matches found by then. */
  filterPartial: false,
  /** "filter" events that came before the set_filter result naming their filterId. */
  /** @type {Map<number, any>} */ earlyFilterEvents: new Map(),
  /** @type {number | null} */ timeRef: null,
  markCount: 0,
  /** Bumped when the rows' contents change (colors, comments…): the overview asks again. */
  rowsVersion: 0,
  /** Bumped by each Find Packet hit or miss: the overview shows its matches. */
  findVersion: 0,
  /** Number of ignored packets (Ctrl+D; the set lives in the backend). */
  ignoredCount: 0,
  /** Back/forward history over jumps (links, go to, find, marks, conversation). */
  /** @type {{back: number[], forward: number[]}} */ nav: { back: [], forward: [] },
  /** Field name → {type, desc} from the backend's field catalogue (frame links, Apply as Column). */
  /** @type {Map<string, {type: string, desc: string}>} */ fieldTypes: new Map(),
  /** "✨ Ask AI": available (host says a model can be used), asking (the input holds a description). */
  /** The ☰ menu's commands (host "commands" message). @type {any[]} */
  commands: [],
  /** The ☰ menu's open headings (the rest start folded), kept in the webview state. */
  /** @type {Set<string>} */ menuGroups: new Set(
    Array.isArray(saved.menuGroups) ? saved.menuGroups : [],
  ),
  ai: {
    available: false,
    asking: false,
    /** @type {number | null} */ request: null,
    savedText: "",
    /** @type {string[]} */ savedClasses: [],
  },
};

let rpcSeq = 0;
/** @type {Map<number, {resolve: (v: any) => void, reject: (e: any) => void}>} */
export const rpcPending = new Map();

/**
 * @param {string} method
 * @param {Record<string, unknown>} params
 * @returns {{id: number, promise: Promise<any>}}
 */
export function rpc(method, params) {
  const id = ++rpcSeq;
  const promise = new Promise((resolve, reject) => {
    rpcPending.set(id, { resolve, reject });
  });
  vscode.postMessage({ type: "rpc", id, method, params });
  return { id, promise };
}

/** @param {number} id */
export function cancelRpc(id) {
  if (rpcPending.has(id)) {
    vscode.postMessage({ type: "cancel", id });
  }
}

export const CANCELLED = -32800;
export const INVALID_FILTER = -32010;
