// @ts-check
/** The ☰ commands menu at the end of the filter bar. */

import { el, icon, isMac, lib, state, vscode } from "./core.js";
import { hideMenu } from "./menu.js";
import { persist } from "./status.js";

/**
 * Every PCAP Lens command, grouped under foldable headings, filtered as
 * you type (lib.groupCommands/filterCommands/commandMenuRows). Groups start
 * folded and the open ones are remembered (`state.menuGroups`); the commands
 * run from here lately come first, under "Recently Used"
 * (`state.recentCommands`); typing shows every match with its heading as a
 * label. Focus stays in the filter
 * box: ↑/↓, Home/End move the active entry (aria-activedescendant), Enter
 * runs it or toggles a heading, → opens a heading, ← goes back to it and
 * folds it, Esc or Tab closes. Entries that can't run now stay listed but
 * disabled, with the reason as their tooltip and in the hint line.
 */
const commandsMenu = (() => {
  const root = document.createElement("div");
  root.id = "commands-menu";
  root.className = "context-menu command-menu hidden";
  const filter = document.createElement("input");
  filter.id = "commands-filter";
  filter.type = "text";
  filter.spellcheck = false;
  filter.autocomplete = "off";
  filter.placeholder = "Filter commands";
  filter.setAttribute("aria-label", "Filter commands");
  filter.setAttribute("aria-controls", "commands-list");
  const list = document.createElement("div");
  list.id = "commands-list";
  list.setAttribute("role", "menu");
  list.setAttribute("aria-label", "PCAP commands");
  const hint = document.createElement("div");
  hint.className = "command-hint hidden";
  hint.setAttribute("aria-live", "polite");
  root.append(filter, list, hint);
  document.body.append(root);
  return { root, filter, list, hint };
})();
/** @type {{items: {group: string, command: any, node: HTMLElement, reason: string | null}[], active: number}} */
const menuView = { items: [], active: -1 };

function commandContext() {
  return {
    selected: state.selectedFrame !== null,
    marks: state.markCount,
    ignored: state.ignoredCount,
    filter: !!state.appliedFilter,
    capturing: !!state.capture?.running,
    ai: state.ai.available,
    colorized: state.colorized,
  };
}

function menuSearching() {
  return commandsMenu.filter.value.trim() !== "";
}

/**
 * @param {{group?: string, id?: string}} [keep] the entry to keep active
 * (a heading by group, a command by id); else the first enabled one.
 */
function renderCommandsMenu(keep) {
  const ctx = commandContext();
  const shown = lib.filterCommands(state.commands, commandsMenu.filter.value);
  const recent = state.recentCommands
    .map((id) => state.commands.find((/** @type {any} */ c) => c.id === id))
    .filter(Boolean);
  const rows = lib.commandMenuRows(
    lib.groupCommands(shown),
    state.menuGroups,
    menuSearching(),
    recent,
  );
  menuView.items = [];
  /** @type {HTMLElement[]} */
  const groups = [];
  /** @type {HTMLElement | null} */
  let group = null;
  for (const row of rows) {
    const index = menuView.items.length;
    if (row.kind === "group") {
      group = document.createElement("div");
      group.setAttribute("role", "group");
      group.setAttribute("aria-label", row.group);
      groups.push(group);
      const heading = document.createElement("div");
      heading.className = "heading";
      const glyph = icon(lib.COMMAND_GROUP_ICONS[row.group] ?? "blank");
      glyph.classList.add("group-icon");
      if (!row.foldable) {
        heading.setAttribute("aria-hidden", "true"); // (a label over search results)
        const label = document.createElement("span");
        label.textContent = row.group;
        heading.append(glyph, label);
        group.append(heading);
        continue;
      }
      heading.classList.add("item");
      heading.id = `command-item-${index}`;
      heading.setAttribute("role", "menuitem");
      heading.setAttribute("aria-expanded", String(row.open));
      heading.dataset.group = row.group;
      const chevron = icon(row.open ? "chevron-down" : "chevron-right");
      chevron.classList.add("chevron");
      const title = document.createElement("span");
      title.className = "title";
      title.textContent = row.group;
      const count = document.createElement("span");
      count.className = "keys count";
      count.textContent = String(row.count);
      heading.append(chevron, glyph, title, count);
      heading.addEventListener("mousemove", () => setActiveCommand(index));
      heading.addEventListener("mousedown", (e) => e.preventDefault()); // (keep focus in the box)
      heading.addEventListener("click", () => toggleMenuGroup(row.group));
      group.append(heading);
      menuView.items.push({ group: row.group, command: null, node: heading, reason: null });
      continue;
    }
    const command = row.command;
    const reason = lib.commandUnavailable(command, ctx);
    const node = document.createElement("div");
    node.id = `command-item-${index}`;
    node.className = "item";
    node.setAttribute("role", "menuitem");
    node.dataset.id = command.id;
    const title = document.createElement("span");
    title.className = "title";
    title.textContent = command.title;
    const keys = document.createElement("span");
    keys.className = "keys";
    keys.textContent = lib.formatKeybinding(command.keys, isMac);
    node.append(title, keys);
    if (reason) {
      node.setAttribute("aria-disabled", "true");
      node.title = reason;
    }
    node.addEventListener("mousemove", () => setActiveCommand(index));
    node.addEventListener("mousedown", (e) => e.preventDefault()); // (keep focus in the box)
    node.addEventListener("click", () => runMenuEntry(index));
    group?.append(node);
    menuView.items.push({ group: row.group, command, node, reason });
  }
  commandsMenu.list.replaceChildren(...groups);
  const kept = menuView.items.findIndex((i) =>
    keep?.id ? i.command?.id === keep.id : !i.command && i.group === keep?.group,
  );
  const first = menuView.items.findIndex((i) => !i.reason);
  setActiveCommand(kept >= 0 ? kept : menuView.items.length ? Math.max(0, first) : -1);
}

/** Open or fold a heading (it stays the active entry). @param {string} group */
function toggleMenuGroup(group) {
  if (state.menuGroups.has(group)) {
    state.menuGroups.delete(group);
  } else {
    state.menuGroups.add(group);
  }
  persist();
  renderCommandsMenu({ group });
}

/** @param {number} index */
function setActiveCommand(index) {
  menuView.items[menuView.active]?.node.classList.remove("active");
  menuView.active = index;
  const item = menuView.items[index];
  if (item) {
    item.node.classList.add("active");
    item.node.scrollIntoView({ block: "nearest" });
    commandsMenu.filter.setAttribute("aria-activedescendant", item.node.id);
  } else {
    commandsMenu.filter.removeAttribute("aria-activedescendant");
  }
  const text = !menuView.items.length
    ? "No matching commands"
    : item?.reason
      ? `${item.command.title}: ${item.reason}`
      : "";
  commandsMenu.hint.textContent = text;
  commandsMenu.hint.classList.toggle("hidden", !text);
}

function commandsMenuOpen() {
  return !commandsMenu.root.classList.contains("hidden");
}

function openCommandsMenu() {
  hideMenu();
  commandsMenu.filter.value = "";
  commandsMenu.root.classList.remove("hidden");
  el.filterMenu.setAttribute("aria-expanded", "true");
  renderCommandsMenu();
  // Below the button, its right edge on the button's, inside the window.
  const button = el.filterMenu.getBoundingClientRect();
  const menu = commandsMenu.root.getBoundingClientRect();
  const left = Math.max(4, Math.min(button.right - menu.width, window.innerWidth - menu.width - 4));
  commandsMenu.root.style.left = `${left}px`;
  commandsMenu.root.style.top = `${button.bottom + 2}px`;
  commandsMenu.root.style.maxHeight = `${Math.max(120, window.innerHeight - button.bottom - 8)}px`;
  commandsMenu.filter.focus();
}

/** @param {boolean} [refocus] give the focus back to the ☰ button */
function closeCommandsMenu(refocus = false) {
  if (!commandsMenuOpen()) {
    return;
  }
  commandsMenu.root.classList.add("hidden");
  el.filterMenu.setAttribute("aria-expanded", "false");
  if (refocus) {
    el.filterMenu.focus();
  }
}

/** Run an enabled entry on this capture (the host checks the id against its list). @param {number} index */
function runMenuEntry(index) {
  const item = menuView.items[index];
  if (!item) {
    return;
  }
  if (!item.command) {
    toggleMenuGroup(item.group);
    return;
  }
  if (item.reason) {
    setActiveCommand(index); // (shows why in the hint line)
    return;
  }
  closeCommandsMenu(true);
  state.recentCommands = lib.rememberCommand(state.recentCommands, item.command.id);
  persist();
  vscode.postMessage({ type: "runCommand", id: item.command.id });
}

/** @param {number} from @param {number} step */
function moveActiveCommand(from, step) {
  const n = menuView.items.length;
  if (n) {
    setActiveCommand((((from + step) % n) + n) % n);
  }
}

el.filterMenu.addEventListener("click", () =>
  commandsMenuOpen() ? closeCommandsMenu(true) : openCommandsMenu(),
);
el.filterMenu.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" && !commandsMenuOpen()) {
    e.preventDefault();
    openCommandsMenu();
  }
});
commandsMenu.filter.addEventListener("input", () => renderCommandsMenu());
commandsMenu.filter.addEventListener("keydown", (e) => {
  switch (e.key) {
    case "ArrowDown":
      moveActiveCommand(menuView.active, 1);
      break;
    case "ArrowUp":
      moveActiveCommand(menuView.active < 0 ? 0 : menuView.active, -1);
      break;
    case "Home":
      setActiveCommand(menuView.items.length ? 0 : -1);
      break;
    case "End":
      setActiveCommand(menuView.items.length - 1);
      break;
    case "Enter":
      runMenuEntry(menuView.active);
      break;
    case "ArrowRight":
    case "ArrowLeft": {
      const item = menuView.items[menuView.active];
      if (menuSearching() || !item) {
        e.stopPropagation(); // (the caret moves in the typed text)
        return;
      }
      const heading = menuView.items.findIndex((i) => !i.command && i.group === item.group);
      const open = state.menuGroups.has(item.group);
      if (e.key === "ArrowRight") {
        if (item.command) {
          break;
        }
        if (open) {
          moveActiveCommand(menuView.active, 1); // (into the group)
        } else {
          toggleMenuGroup(item.group);
        }
      } else if (item.command) {
        if (heading >= 0) {
          setActiveCommand(heading); // (Recently Used has no heading to go back to)
        }
      } else if (open) {
        toggleMenuGroup(item.group);
      }
      break;
    }
    case "Escape":
    case "Tab":
      closeCommandsMenu(true);
      break;
    default:
      e.stopPropagation(); // (typing filters; the viewer's own keys stay out of it)
      return;
  }
  e.preventDefault();
  e.stopPropagation();
});
window.addEventListener("mousedown", (e) => {
  const t = /** @type {Node} */ (e.target);
  if (commandsMenuOpen() && !commandsMenu.root.contains(t) && !el.filterMenu.contains(t)) {
    closeCommandsMenu();
  }
});
window.addEventListener("blur", () => closeCommandsMenu());
