// @ts-check
/**
 * Packet window (Show Packet in New Window) and File Format view: one detail
 * tree (a flat ARIA tree: levels, expand/collapse, arrow keys) over a hex dump
 * of its byte sources, the selected field's bytes highlighted. The host sends
 * `show {title, note?, frame?, tree, sources}`; picking a field enables Apply
 * / Prepare as Filter and Copy Value. Untrusted text only goes through
 * textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;

  /**
   * @param {string} tag @param {Record<string, string>} [attrs]
   * @param {(Node | string)[]} [children]
   */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") {
        node.className = v;
      } else {
        node.setAttribute(k, v);
      }
    }
    node.append(...children);
    return node;
  }
  const icon = (/** @type {string} */ name) =>
    h("span", { class: `codicon codicon-${name}`, "aria-hidden": "true" });

  /**
   * @typedef {{id: number, label: string, name?: string, show?: string, proto?: boolean,
   *   src?: number, pos?: number, size?: number, children?: TreeNode[]}} TreeNode
   */
  const state = {
    /** @type {TreeNode[]} */ tree: [],
    /** @type {{name: string, hex: string}[]} */ sources: [],
    /** @type {Uint8Array[]} */ bytes: [],
    /** @type {number | null} */ frame: null,
    /** @type {Set<number>} */ open: new Set(),
    /** @type {TreeNode | null} */ selected: null,
    source: 0,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));
  const title = h("h1", { class: "panel-title" });
  const note = h("div", { class: "notice hidden", role: "note" });
  const status = h("div", { class: "status", role: "status" });
  const gotoBtn = h("button", { type: "button", class: "secondary hidden" }, ["Go to Packet"]);
  const applyBtn = h("button", { type: "button", disabled: "" }, ["Apply as Filter"]);
  const prepareBtn = h("button", { type: "button", class: "secondary", disabled: "" }, [
    "Prepare as Filter",
  ]);
  const copyBtn = h("button", { type: "button", class: "secondary", disabled: "" }, ["Copy Value"]);
  const expandBtn = h("button", { type: "button", class: "icon", "aria-label": "Expand all" }, [
    icon("expand-all"),
  ]);
  const collapseBtn = h("button", { type: "button", class: "icon", "aria-label": "Collapse all" }, [
    icon("collapse-all"),
  ]);
  const toolbar = h("div", { class: "toolbar", role: "toolbar", "aria-label": "Field actions" }, [
    applyBtn,
    prepareBtn,
    copyBtn,
    gotoBtn,
    h("span", { class: "spacer" }),
    expandBtn,
    collapseBtn,
  ]);
  const treeBox = h("div", {
    class: "packet-tree",
    role: "tree",
    "aria-label": "Details",
    id: "packet-tree",
  });
  const tabs = h("div", { class: "packet-sources hidden", role: "tablist", "aria-label": "Bytes" });
  const hexBox = h("div", {
    class: "packet-hex",
    role: "region",
    "aria-label": "Bytes",
    tabindex: "0",
  });
  app.append(title, note, toolbar, status, treeBox, tabs, hexBox);

  // ------------------------------------------------------------------ tree

  /** The visible nodes in order, with their level, position and set size. */
  function visibleNodes() {
    /** @type {{node: TreeNode, level: number, pos: number, size: number}[]} */
    const out = [];
    const walk = (/** @type {TreeNode[]} */ nodes, /** @type {number} */ level) => {
      nodes.forEach((node, i) => {
        out.push({ node, level, pos: i + 1, size: nodes.length });
        if (node.children?.length && state.open.has(node.id)) {
          walk(node.children, level + 1);
        }
      });
    };
    walk(state.tree, 1);
    return out;
  }

  function renderTree() {
    const rows = visibleNodes();
    if (!state.selected && rows.length) {
      state.selected = rows[0].node;
    }
    treeBox.replaceChildren(
      ...rows.map(({ node, level, pos, size }) => {
        const parent = !!node.children?.length;
        const selected = node === state.selected;
        const row = h(
          "div",
          {
            role: "treeitem",
            class: `packet-node${selected ? " selected" : ""}`,
            id: `node-${node.id}`,
            "aria-level": String(level),
            "aria-posinset": String(pos),
            "aria-setsize": String(size),
            "aria-selected": String(selected),
            tabindex: selected ? "0" : "-1",
          },
          [
            parent
              ? icon(state.open.has(node.id) ? "chevron-down" : "chevron-right")
              : h("span", { class: "twistie", "aria-hidden": "true" }),
            node.label,
          ],
        );
        if (parent) {
          row.setAttribute("aria-expanded", String(state.open.has(node.id)));
        }
        row.style.setProperty("--depth", String(level - 1));
        row.addEventListener("click", () => select(node, true));
        row.addEventListener("dblclick", () => parent && toggle(node));
        return row;
      }),
    );
  }

  /** @param {TreeNode} node @param {boolean} [focus] */
  function select(node, focus = false) {
    state.selected = node;
    if (node.src !== undefined && node.src !== state.source && state.bytes[node.src]) {
      state.source = node.src;
      renderTabs();
    }
    renderTree();
    renderHex();
    updateActions();
    const row = document.getElementById(`node-${node.id}`);
    row?.scrollIntoView({ block: "nearest" });
    if (focus) {
      row?.focus();
    }
  }

  /** @param {TreeNode} node */
  function toggle(node) {
    if (state.open.has(node.id)) {
      state.open.delete(node.id);
    } else {
      state.open.add(node.id);
    }
    select(node, true);
  }

  treeBox.addEventListener("keydown", (e) => {
    const rows = visibleNodes();
    const i = rows.findIndex((r) => r.node === state.selected);
    if (i < 0) {
      return;
    }
    const { node, level } = rows[i];
    const parent = !!node.children?.length;
    let next = null;
    switch (e.key) {
      case "ArrowDown":
        next = rows[i + 1]?.node;
        break;
      case "ArrowUp":
        next = rows[i - 1]?.node;
        break;
      case "Home":
        next = rows[0]?.node;
        break;
      case "End":
        next = rows[rows.length - 1]?.node;
        break;
      case "ArrowRight":
        if (parent && !state.open.has(node.id)) {
          toggle(node);
        } else if (parent) {
          next = rows[i + 1]?.node;
        }
        break;
      case "ArrowLeft":
        if (parent && state.open.has(node.id)) {
          toggle(node);
        } else {
          // To the parent: the closest row above with a lower level.
          next = rows
            .slice(0, i)
            .reverse()
            .find((r) => r.level < level)?.node;
        }
        break;
      case "Enter":
        filter(true);
        break;
      default:
        return;
    }
    e.preventDefault();
    if (next) {
      select(next, true);
    }
  });

  expandBtn.addEventListener("click", () => {
    const walk = (/** @type {TreeNode[]} */ nodes) =>
      nodes.forEach((n) => {
        if (n.children?.length) {
          state.open.add(n.id);
          walk(n.children);
        }
      });
    walk(state.tree);
    renderTree();
  });
  collapseBtn.addEventListener("click", () => {
    state.open.clear();
    // (The selection may be inside a closed node: select its top level.)
    const top = state.tree.find((n) => contains(n, state.selected));
    if (top) {
      state.selected = top;
    }
    renderTree();
    renderHex();
    updateActions();
  });

  /** @param {TreeNode} node @param {TreeNode | null} target */
  function contains(node, target) {
    return node === target || !!node.children?.some((c) => contains(c, target));
  }

  // ------------------------------------------------------------------ bytes

  function renderTabs() {
    tabs.classList.toggle("hidden", state.sources.length < 2);
    tabs.replaceChildren(
      ...state.sources.map((src, i) => {
        const tab = h(
          "button",
          {
            type: "button",
            role: "tab",
            "aria-selected": String(i === state.source),
            tabindex: i === state.source ? "0" : "-1",
          },
          [`${src.name} (${state.bytes[i].length} bytes)`],
        );
        tab.addEventListener("click", () => {
          state.source = i;
          renderTabs();
          renderHex();
        });
        return tab;
      }),
    );
  }

  /** The selected node's byte range in the shown source, or [0, 0]. */
  function highlight() {
    const n = state.selected;
    if (!n || n.pos === undefined || !n.size || (n.src ?? 0) !== state.source) {
      return [0, 0];
    }
    return [n.pos, n.pos + n.size];
  }

  function renderHex() {
    const bytes = state.bytes[state.source] ?? new Uint8Array();
    const [start, end] = highlight();
    const rows = [];
    for (let row = 0; row < bytes.length; row += 16) {
      const parts = lib.hexRowParts(bytes, row, start, end);
      const piece = (/** @type {[string, boolean][]} */ list) =>
        list.map(([text, hi]) => (hi ? h("mark", {}, [text]) : document.createTextNode(text)));
      const line = h("div", { class: "hex-row" }, [
        h("span", { class: "hex-offset" }, [parts.offset]),
        h("span", { class: "hex-bytes" }, piece(parts.hex)),
        h("span", { class: "hex-ascii" }, piece(parts.ascii)),
      ]);
      if (end > start && row + 16 > start && row < end) {
        line.classList.add("marked");
      }
      rows.push(line);
    }
    hexBox.replaceChildren(...rows);
    hexBox.querySelector(".hex-row.marked")?.scrollIntoView({ block: "nearest" });
  }

  // ------------------------------------------------------------------ actions

  function updateActions() {
    const n = state.selected;
    const expr = n ? lib.buildFieldFilter(n) : null;
    applyBtn.toggleAttribute("disabled", !expr);
    prepareBtn.toggleAttribute("disabled", !expr);
    copyBtn.toggleAttribute("disabled", !n || n.show === undefined);
  }

  /** @param {boolean} apply */
  function filter(apply) {
    const expr = state.selected ? lib.buildFieldFilter(state.selected) : null;
    if (expr) {
      vscode.postMessage({ type: "filter", expr, apply });
    }
  }

  applyBtn.addEventListener("click", () => filter(true));
  prepareBtn.addEventListener("click", () => filter(false));
  copyBtn.addEventListener("click", () => {
    if (state.selected?.show !== undefined) {
      vscode.postMessage({ type: "copy", text: state.selected.show });
    }
  });
  gotoBtn.addEventListener("click", () => {
    if (state.frame !== null) {
      vscode.postMessage({ type: "goto", frame: state.frame });
    }
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "show") {
      title.textContent = msg.title;
      note.textContent = msg.note ?? "";
      note.classList.toggle("hidden", !msg.note);
      status.textContent = "";
      state.tree = msg.tree ?? [];
      state.sources = msg.sources ?? [];
      state.bytes = state.sources.map((s) => lib.hexToBytes(s.hex));
      state.frame = typeof msg.frame === "number" ? msg.frame : null;
      gotoBtn.classList.toggle("hidden", state.frame === null);
      // Top-level protocols start open, as in the viewer's details (but not
      // a file's own tree: a pcapng has a node per block).
      state.open = new Set(
        msg.expand === false
          ? state.tree.slice(0, 1).map((n) => n.id)
          : state.tree.map((n) => n.id),
      );
      state.selected = null;
      state.source = 0;
      renderTabs();
      renderTree();
      renderHex();
      updateActions();
    } else if (msg.type === "error") {
      status.textContent = msg.message;
    }
  });

  vscode.postMessage({ type: "ready" });
})();
