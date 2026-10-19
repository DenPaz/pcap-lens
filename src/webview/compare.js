// @ts-check
/**
 * Compare Packets panel: two packets' detail trees side by side, aligned by
 * field (lib.comparePackets), with the fields that differ marked. "Only
 * differences" hides the rows that are the same in both (keeping the
 * protocols and parents of those that differ).
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  /** Rows drawn at most (a packet pair can have thousands of fields). */
  const MAX_ROWS = 5000;
  /** Indentation per tree level, in px. */
  const INDENT = 14;

  const state = {
    /** @type {{number: number, tree: any[]}[] | null} */ packets: null,
    /** @type {ReturnType<typeof lib.comparePackets>} */ rows: [],
    onlyDifferences: true,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  /** @param {string} tag @param {Record<string, string>} [attrs] @param {(Node | string)[]} [children] */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, v);
    }
    node.append(...children);
    return node;
  }

  /** A Codicons glyph (codicons/codicon.css), hidden from screen readers. @param {string} name */
  const icon = (name) => h("span", { class: `codicon codicon-${name}`, "aria-hidden": "true" });

  const title = h("h1", { class: "panel-title" }, ["Compare Packets"]);
  const only = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox", id: "cmp-only" }));
  only.checked = state.onlyDifferences;
  const swap = h("button", { type: "button", class: "secondary", id: "cmp-swap" }, [
    icon("arrow-swap"),
    " Swap",
  ]);
  const gotoA = h("button", { type: "button", class: "secondary", id: "cmp-goto-a" });
  const gotoB = h("button", { type: "button", class: "secondary", id: "cmp-goto-b" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" }, [
    h("label", {}, [only, "Only differences"]),
    swap,
    h("span", { class: "spacer" }),
    gotoA,
    gotoB,
  ]);
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const headA = h("th", { scope: "col" });
  const headB = h("th", { scope: "col" });
  const body = h("tbody");
  const table = h("table", { class: "stats compare hidden" }, [
    h("thead", {}, [
      h("tr", {}, [
        h("th", { scope: "col", class: "cmp-mark" }, [
          h("span", { class: "visually-hidden" }, ["Difference"]),
        ]),
        headA,
        headB,
      ]),
    ]),
    body,
  ]);
  app.append(title, toolbar, notice, status, table);

  only.addEventListener("change", () => {
    state.onlyDifferences = only.checked;
    render();
  });
  swap.addEventListener("click", () => vscode.postMessage({ type: "swap" }));
  gotoA.addEventListener("click", () => goto(0));
  gotoB.addEventListener("click", () => goto(1));

  /** @param {0 | 1} side */
  function goto(side) {
    const p = state.packets?.[side];
    if (p) {
      vscode.postMessage({ type: "goto", frame: p.number });
    }
  }

  window.addEventListener("message", (event) => {
    // VS Code posts to this frame with its own origin as the target; ignore other senders.
    if (event.origin !== window.origin) {
      return;
    }
    const msg = event.data;
    switch (msg.type) {
      case "loading":
        status.textContent = `Reading packets ${msg.frames[0]} and ${msg.frames[1]}…`;
        notice.classList.add("hidden");
        break;
      case "show":
        state.packets = [msg.a, msg.b];
        state.rows = lib.comparePackets(msg.a.tree, msg.b.tree);
        notice.classList.add("hidden");
        render();
        break;
      case "error":
        notice.textContent = msg.message;
        notice.classList.remove("hidden");
        status.textContent = "";
        break;
    }
  });

  function render() {
    const packets = state.packets;
    if (!packets) {
      return;
    }
    const [a, b] = packets;
    title.textContent = `Compare Packets ${a.number} and ${b.number}`;
    headA.textContent = `Packet ${a.number}`;
    headB.textContent = `Packet ${b.number}`;
    gotoA.textContent = `Go to Packet ${a.number}`;
    gotoB.textContent = `Go to Packet ${b.number}`;
    const counts = { changed: 0, a: 0, b: 0 };
    for (const r of state.rows) {
      if (r.status !== "same") {
        counts[r.status]++;
      }
    }
    status.textContent =
      counts.changed + counts.a + counts.b === 0
        ? "The two packets' details are the same."
        : [
            `${counts.changed.toLocaleString()} field${counts.changed === 1 ? "" : "s"} differ`,
            `${counts.a.toLocaleString()} only in packet ${a.number}`,
            `${counts.b.toLocaleString()} only in packet ${b.number}`,
          ].join(" · ");
    const shown = state.onlyDifferences ? state.rows.filter((r) => r.differs) : state.rows;
    const frag = document.createDocumentFragment();
    for (const r of shown.slice(0, MAX_ROWS)) {
      frag.append(row(r, a.number, b.number));
    }
    if (shown.length > MAX_ROWS) {
      frag.append(
        h("tr", {}, [
          h("td", { colspan: "3", class: "cmp-more" }, [
            `${(shown.length - MAX_ROWS).toLocaleString()} more rows not shown.`,
          ]),
        ]),
      );
    }
    body.replaceChildren(frag);
    table.classList.toggle("hidden", !shown.length);
  }

  /**
   * What a row's mark says, for screen readers and as its tooltip.
   * @param {string} statusName @param {number} na @param {number} nb
   */
  function describe(statusName, na, nb) {
    switch (statusName) {
      case "changed":
        return "Differs";
      case "a":
        return `Only in packet ${na}`;
      case "b":
        return `Only in packet ${nb}`;
      default:
        return "Same";
    }
  }

  /** @param {any} r @param {number} na @param {number} nb */
  function row(r, na, nb) {
    const what = describe(r.status, na, nb);
    const glyph = { changed: "diff-modified", a: "diff-removed", b: "diff-added" }[
      /** @type {"changed" | "a" | "b"} */ (r.status)
    ];
    const mark = h("td", { class: "cmp-mark", title: what }, [
      ...(glyph ? [icon(glyph)] : []),
      h("span", { class: "visually-hidden" }, [what]),
    ]);
    /** @param {string | null} text @param {string} side */
    const cell = (text, side) => {
      const td = h("td", { class: `cmp-cell cmp-${side}` }, [text ?? ""]);
      td.style.paddingLeft = `calc(var(--space-4) + ${r.depth * INDENT}px)`;
      return td;
    };
    const tr = h("tr", { class: `cmp-${r.status}${r.depth === 0 ? " cmp-proto" : ""}` }, [
      mark,
      cell(r.a, "a"),
      cell(r.b, "b"),
    ]);
    return tr;
  }

  vscode.postMessage({ type: "ready" });
})();
