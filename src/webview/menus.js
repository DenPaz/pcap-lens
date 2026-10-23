// @ts-check
/**
 * Context menus for the viewer and the panels (a classic script: exposes
 * `window.PcapMenus`): a root menu (#context-menu, created when the page has
 * none) and submenus beside the item that opens them, VS Code style. Each
 * item can carry a Codicon, a dimmed hint (the filter it applies), its key
 * binding, a check mark, or children (a list, or a function that fetches
 * them: "Loading…" meanwhile).
 *
 * Mouse: hovering an item with children opens its submenu (after a short
 * delay, so crossing the menu diagonally doesn't flicker). Keyboard: the menu
 * takes the focus; ↑/↓, Home/End move over the enabled items, → or Enter
 * opens a submenu, ← or Esc closes it, Enter or Space runs an item, a
 * letter jumps to the next item starting with it, Esc on the root (or Tab)
 * closes everything and gives the focus back. Built with createElement;
 * positions are set through CSSOM (allowed by the CSP).
 */
(function () {
  "use strict";

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

  /** The root menu element (the page's #context-menu, else one made here). */
  function root() {
    let box = document.getElementById("context-menu");
    if (!box) {
      box = document.createElement("div");
      box.id = "context-menu";
      box.className = "context-menu hidden";
      box.setAttribute("role", "menu");
      document.body.append(box);
    }
    return box;
  }

  /** A Codicons glyph, hidden from screen readers. @param {string} name */
  function icon(name) {
    const span = document.createElement("span");
    span.className = `codicon codicon-${name}`;
    span.setAttribute("aria-hidden", "true");
    return span;
  }

  const OPEN_DELAY_MS = 150;

  /**
   * @typedef {object} Pane
   * @property {HTMLElement} el
   * @property {MenuEntry[]} entries
   * @property {HTMLElement[]} items the rendered items, parallel to the non-separator entries
   * @property {MenuItem[]} models
   * @property {number} active
   */

  /** @type {Pane[]} */
  const panes = [];
  /** @type {Element | null} */
  let returnFocus = null;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let hoverTimer;
  let generation = 0;

  /** @param {MenuEntry | MenuTuple} entry @returns {MenuEntry} */
  function normalize(entry) {
    if (entry === "-" || !Array.isArray(entry)) {
      return entry;
    }
    const [label, action, checked] = entry;
    return label === "-" ? "-" : { label, action, checked };
  }

  /** @param {MenuItem} item */
  const enabled = (item) => item.action !== null && (item.action || item.children);

  /**
   * Open a menu at (x, y) (viewport coordinates; it stays inside the window).
   * @param {number} x @param {number} y @param {(MenuEntry | MenuTuple)[]} entries
   */
  function showMenu(x, y, entries) {
    closeFrom(0);
    generation++;
    if (!root().contains(document.activeElement)) {
      returnFocus = document.activeElement;
    }
    const pane = render(root(), entries.map(normalize), 0);
    root().classList.remove("hidden");
    place(root(), x, y);
    panes.push(pane);
    root().focus({ preventScroll: true });
  }

  /** Close every menu (and give the focus back when `restore`). @param {boolean} [restore] */
  function hideMenu(restore = false) {
    clearTimeout(hoverTimer);
    closeFrom(0);
    root().classList.add("hidden");
    if (restore && returnFocus instanceof HTMLElement && returnFocus.isConnected) {
      returnFocus.focus({ preventScroll: true });
    }
    returnFocus = null;
  }

  /** Whether a menu is open. */
  const menuOpen = () => !root().classList.contains("hidden");

  /** Close the panes from `level` on (0 = all; the root element is only emptied). @param {number} level */
  function closeFrom(level) {
    while (panes.length > level) {
      const pane = /** @type {Pane} */ (panes.pop());
      if (pane.el === root()) {
        pane.el.replaceChildren();
      } else {
        pane.el.remove();
      }
    }
    const parent = panes[level - 1];
    if (parent) {
      for (const item of parent.items) {
        if (item.hasAttribute("aria-expanded")) {
          item.setAttribute("aria-expanded", "false");
        }
      }
    }
  }

  /**
   * Fill `box` with the entries' items.
   * @param {HTMLElement} box @param {MenuEntry[]} entries @param {number} level
   * @returns {Pane}
   */
  function render(box, entries, level) {
    /** @type {Pane} */
    const pane = { el: box, entries, items: [], models: [], active: -1 };
    box.setAttribute("role", "menu");
    box.tabIndex = -1;
    const checkable = entries.some((e) => e !== "-" && e.checked !== undefined);
    const withIcons = checkable || entries.some((e) => e !== "-" && e.icon);
    box.classList.toggle("with-icons", withIcons);
    box.replaceChildren(
      ...entries.map((entry) => {
        if (entry === "-") {
          const sep = document.createElement("div");
          sep.className = "sep";
          sep.setAttribute("role", "separator");
          return sep;
        }
        const item = document.createElement("div");
        const index = pane.items.length;
        pane.items.push(item);
        pane.models.push(entry);
        item.className = "item" + (enabled(entry) ? "" : " disabled");
        item.setAttribute("role", entry.checked !== undefined ? "menuitemcheckbox" : "menuitem");
        item.tabIndex = -1;
        if (!enabled(entry)) {
          item.setAttribute("aria-disabled", "true");
        }
        if (entry.checked !== undefined) {
          item.setAttribute("aria-checked", String(entry.checked));
          item.classList.add("checkable");
        }
        if (entry.title) {
          item.title = entry.title;
        }
        if (withIcons) {
          const glyph =
            entry.checked !== undefined ? (entry.checked ? "check" : "blank") : entry.icon;
          const slot = icon(glyph || "blank");
          slot.classList.add("menu-icon");
          item.append(slot);
        }
        const label = document.createElement("span");
        label.className = "label";
        label.textContent = entry.label;
        item.append(label);
        if (entry.hint) {
          const hint = document.createElement("span");
          hint.className = "hint";
          hint.textContent = entry.hint;
          item.append(hint);
        }
        if (entry.keys) {
          const keys = document.createElement("span");
          keys.className = "keys";
          keys.textContent = entry.keys;
          item.append(keys);
        }
        if (entry.children) {
          item.setAttribute("aria-haspopup", "menu");
          item.setAttribute("aria-expanded", "false");
          const chevron = icon("chevron-right");
          chevron.classList.add("submenu-chevron");
          item.append(chevron);
        }
        item.addEventListener("mouseenter", () => {
          clearTimeout(hoverTimer);
          setActive(level, index, false);
          hoverTimer = setTimeout(() => {
            if (entry.children && enabled(entry)) {
              void openSubmenu(level, index, false);
            } else {
              closeFrom(level + 1);
            }
          }, OPEN_DELAY_MS);
        });
        item.addEventListener("click", (e) => {
          e.stopPropagation();
          activate(level, index, false);
        });
        return item;
      }),
    );
    return pane;
  }

  /** Keep a menu inside the window. @param {HTMLElement} box @param {number} x @param {number} y */
  function place(box, x, y) {
    const rect = box.getBoundingClientRect();
    box.style.left = `${Math.max(4, Math.min(x, window.innerWidth - rect.width - 4))}px`;
    box.style.top = `${Math.max(4, Math.min(y, window.innerHeight - rect.height - 4))}px`;
  }

  /**
   * Highlight item `index` of pane `level` (and focus it for the keyboard).
   * @param {number} level @param {number} index @param {boolean} focus
   */
  function setActive(level, index, focus) {
    const pane = panes[level];
    if (!pane) {
      return;
    }
    pane.items[pane.active]?.classList.remove("active");
    pane.active = index;
    const item = pane.items[index];
    if (item) {
      item.classList.add("active");
      if (focus) {
        item.focus({ preventScroll: false });
      }
    }
  }

  /**
   * Run an item, or open its submenu.
   * @param {number} level @param {number} index @param {boolean} keyboard
   */
  function activate(level, index, keyboard) {
    const pane = panes[level];
    const model = pane?.models[index];
    if (!model || !enabled(model)) {
      return;
    }
    if (model.children) {
      clearTimeout(hoverTimer);
      void openSubmenu(level, index, keyboard);
      return;
    }
    hideMenu(false);
    model.action?.();
  }

  /**
   * Open the submenu of item `index` of pane `level` beside it.
   * @param {number} level @param {number} index @param {boolean} focusFirst
   */
  async function openSubmenu(level, index, focusFirst) {
    const pane = panes[level];
    const model = pane?.models[index];
    const item = pane?.items[index];
    if (!pane || !model || !item || !model.children) {
      return;
    }
    const open = panes[level + 1];
    if (open && open.el.dataset.parent === String(index)) {
      if (focusFirst) {
        moveActive(level + 1, 1, -1);
      }
      return;
    }
    closeFrom(level + 1);
    const box = document.createElement("div");
    box.className = "context-menu submenu";
    box.id = `context-menu-${level + 1}`;
    box.dataset.parent = String(index);
    box.setAttribute("aria-label", model.label);
    item.setAttribute("aria-expanded", "true");
    item.setAttribute("aria-controls", box.id);
    document.body.append(box);
    const children = model.children;
    const loading = typeof children === "function";
    const sub = render(box, loading ? [{ label: "Loading…", action: null }] : children, level + 1);
    panes.push(sub);
    placeBeside(box, item);
    if (focusFirst && !loading) {
      moveActive(level + 1, 1, -1);
    }
    if (loading) {
      const mine = generation;
      /** @type {MenuEntry[]} */
      let entries;
      try {
        entries = await children();
      } catch {
        entries = [{ label: "Not available", action: null }];
      }
      if (mine !== generation || panes[level + 1] !== sub) {
        return; // closed or replaced meanwhile
      }
      const filled = render(
        box,
        entries.length ? entries : [{ label: "None", action: null }],
        level + 1,
      );
      panes[level + 1] = filled;
      placeBeside(box, item);
      if (focusFirst || document.activeElement === box) {
        moveActive(level + 1, 1, -1);
      }
    }
  }

  /** Put a submenu to the right of its item, else to the left. @param {HTMLElement} box @param {HTMLElement} item */
  function placeBeside(box, item) {
    const at = item.getBoundingClientRect();
    const rect = box.getBoundingClientRect();
    const parent = /** @type {HTMLElement} */ (item.parentElement).getBoundingClientRect();
    const right = parent.right - 2;
    const x = right + rect.width <= window.innerWidth - 4 ? right : parent.left - rect.width + 2;
    place(box, x, at.top - 4);
  }

  /**
   * Move the active item of pane `level` by `step` over the enabled items,
   * from `from` (default: the active one), wrapping.
   * @param {number} level @param {number} step @param {number} [from]
   */
  function moveActive(level, step, from) {
    const pane = panes[level];
    if (!pane || !pane.items.length) {
      return;
    }
    const n = pane.items.length;
    let i = from ?? pane.active;
    for (let tries = 0; tries < n; tries++) {
      i = (((i + step) % n) + n) % n;
      if (enabled(pane.models[i])) {
        setActive(level, i, true);
        return;
      }
    }
    pane.el.focus({ preventScroll: true });
  }

  /** The pane the keyboard is in: the deepest one that holds the focus, else the deepest. */
  function currentLevel() {
    for (let level = panes.length - 1; level >= 0; level--) {
      if (panes[level].el.contains(document.activeElement)) {
        return level;
      }
    }
    return panes.length - 1;
  }

  document.addEventListener(
    "keydown",
    (e) => {
      if (!panes.length) {
        return;
      }
      const level = currentLevel();
      const pane = panes[level];
      switch (e.key) {
        case "ArrowDown":
          moveActive(level, 1);
          break;
        case "ArrowUp":
          moveActive(level, -1, pane.active < 0 ? 0 : pane.active);
          break;
        case "Home":
          moveActive(level, 1, -1);
          break;
        case "End":
          moveActive(level, -1, 0);
          break;
        case "ArrowRight":
          if (pane.models[pane.active]?.children) {
            void openSubmenu(level, pane.active, true);
          }
          break;
        case "ArrowLeft":
          if (level > 0) {
            closeFrom(level);
            setActive(level - 1, panes[level - 1].active, true);
          }
          break;
        case "Enter":
        case " ":
          if (pane.active >= 0) {
            activate(level, pane.active, true);
          }
          break;
        case "Escape":
          if (level > 0) {
            closeFrom(level);
            setActive(level - 1, panes[level - 1].active, true);
          } else {
            hideMenu(true);
          }
          break;
        case "Tab":
          hideMenu(true);
          break;
        default:
          if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
            typeahead(level, e.key);
            break;
          }
          return; // (other keys go on as usual)
      }
      e.preventDefault();
      e.stopPropagation();
    },
    true,
  );

  /** Jump to the next enabled item starting with `ch`. @param {number} level @param {string} ch */
  function typeahead(level, ch) {
    const pane = panes[level];
    const n = pane.items.length;
    const want = ch.toLowerCase();
    for (let step = 1; step <= n; step++) {
      const i = (pane.active + step + n) % n;
      const model = pane.models[i];
      if (enabled(model) && model.label.toLowerCase().startsWith(want)) {
        setActive(level, i, true);
        return;
      }
    }
  }

  window.addEventListener("mousedown", (e) => {
    const target = /** @type {Node} */ (e.target);
    if (panes.length && !panes.some((p) => p.el.contains(target))) {
      hideMenu(false);
    }
  });
  window.addEventListener("blur", () => hideMenu(false));
  window.addEventListener("resize", () => hideMenu(false));

  /** @type {any} */ (window).PcapMenus = { show: showMenu, hide: hideMenu, isOpen: menuOpen };
})();
