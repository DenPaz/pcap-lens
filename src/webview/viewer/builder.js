// @ts-check
/**
 * The display filter builder (the filter bar's button, "PCAP: Build Display
 * Filter…", the details' "Build Filter from Field…", the empty list): pick a
 * field by name or description (field_index `words`), a relation for its type
 * (lib.builderOperators) and a value, typed or picked from the values seen in
 * the capture (field_values), then apply the filter or put it in the bar,
 * alone or combined with the filter there (lib.combineFilter).
 */

import { CANCELLED, cancelRpc, el, lib, rpc } from "./core.js";
import { applyFilter, validateSoon } from "./filterbar.js";

const FIELD_LIMIT = 50;
/** The field chosen: name, type (FT_* or "protocol") and display name. */
/** @type {{name: string, type: string, desc: string} | null} */
let field = null;
/** The search's results and the active one (aria-activedescendant). */
/** @type {{name: string, type?: string, desc?: string}[]} */
let fieldItems = [];
let activeField = -1;
/** @type {{value: string, count: number}[]} */
let valueItems = [];
let activeValue = -1;
let searchTimer = 0;
let searchSeq = 0;
/** @type {number | null} */
let valuesRequest = null;
let validateTimer = 0;
let validateSeq = 0;
/** The filter the dialog makes now ("" when incomplete) and whether tshark accepts it. */
let expr = "";
let valid = false;
/** @type {HTMLElement | null} */
let returnFocus = null;

/**
 * Open the builder, optionally with a field (and a value) chosen already.
 * `returnTo` gets the focus back on close (e.g. the details tree, for its
 * menu: a menu item that had the focus is hidden by then).
 * @param {{field?: string, value?: string, returnTo?: HTMLElement}} [opts]
 */
export function openFilterBuilder(opts = {}) {
  returnFocus = opts.returnTo ?? /** @type {HTMLElement | null} */ (document.activeElement);
  field = null;
  el.builderSearch.value = opts.field ?? "";
  el.builderValue.value = "";
  el.builderCombine.value = el.filterInput.value.trim() ? "and" : "replace";
  hideFields();
  clearValues();
  setField(null);
  el.builder.classList.remove("hidden");
  if (opts.field) {
    void chooseByName(opts.field, opts.value);
  } else {
    el.builderSearch.focus();
  }
}

export function closeFilterBuilder() {
  if (el.builder.classList.contains("hidden")) {
    return;
  }
  el.builder.classList.add("hidden");
  stopValues();
  window.clearTimeout(searchTimer);
  window.clearTimeout(validateTimer);
  searchSeq++;
  validateSeq++;
  const visible = returnFocus?.isConnected && returnFocus.offsetParent !== null;
  const target = visible && returnFocus ? returnFocus : el.filterInput;
  returnFocus = null;
  target.focus();
}

/** @param {string} name @param {string} [value] */
async function chooseByName(name, value) {
  try {
    const res = await rpc("field_types", { names: [name] }).promise;
    const t = res.types[name];
    chooseField({ name, type: t?.type ?? "protocol", desc: t?.desc ?? "" }, value);
  } catch {
    el.builderSearch.focus();
  }
}

/* ------------------------------------------------------------- field search */

el.builderSearch.addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(searchFields, 150);
});

async function searchFields() {
  const words = el.builderSearch.value.trim();
  const seq = ++searchSeq;
  if (!words) {
    hideFields();
    return;
  }
  try {
    const res = await rpc("field_index", { words, limit: FIELD_LIMIT }).promise;
    if (seq === searchSeq) {
      showFields(res.fields);
    }
  } catch {
    /* the search is best-effort */
  }
}

/** @param {{name: string, type?: string, desc?: string}[]} items */
function showFields(items) {
  fieldItems = items;
  activeField = items.length ? 0 : -1;
  const rows = items.map((item, i) => {
    const row = document.createElement("div");
    row.id = `builder-field-${i}`;
    row.setAttribute("role", "option");
    const name = document.createElement("span");
    name.textContent = item.name;
    const desc = document.createElement("span");
    desc.className = "builder-desc";
    desc.textContent = item.desc ?? "";
    row.append(name, desc);
    row.addEventListener("mousedown", (e) => e.preventDefault()); // keep focus in the box
    row.addEventListener("click", () => chooseField(fieldEntry(item)));
    return row;
  });
  if (!rows.length) {
    const none = document.createElement("div");
    none.className = "builder-note";
    none.textContent = "No field or protocol matches.";
    rows.push(none);
  }
  el.builderFields.replaceChildren(...rows);
  el.builderFields.classList.remove("hidden");
  el.builderSearch.setAttribute("aria-expanded", "true");
  markActive(el.builderFields, el.builderSearch, activeField, "builder-field-");
}

function hideFields() {
  fieldItems = [];
  activeField = -1;
  el.builderFields.classList.add("hidden");
  el.builderFields.replaceChildren();
  el.builderSearch.setAttribute("aria-expanded", "false");
  el.builderSearch.removeAttribute("aria-activedescendant");
}

/** @param {{name: string, type?: string, desc?: string}} item */
function fieldEntry(item) {
  return { name: item.name, type: item.type ?? "protocol", desc: item.desc ?? "" };
}

/**
 * The option `index` of `list` is the active one (selected look, scrolled to,
 * named by `owner`'s aria-activedescendant).
 * @param {HTMLElement} list @param {HTMLElement} owner @param {number} index @param {string} prefix
 */
function markActive(list, owner, index, prefix) {
  for (const option of list.querySelectorAll('[role="option"]')) {
    option.setAttribute("aria-selected", String(option.id === `${prefix}${index}`));
  }
  const active = index >= 0 ? document.getElementById(`${prefix}${index}`) : null;
  if (active) {
    owner.setAttribute("aria-activedescendant", active.id);
    active.scrollIntoView({ block: "nearest" });
  } else {
    owner.removeAttribute("aria-activedescendant");
  }
}

el.builderSearch.addEventListener("keydown", (e) => {
  const open = fieldItems.length > 0;
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    if (!open) {
      void searchFields();
      return;
    }
    const step = e.key === "ArrowDown" ? 1 : -1;
    activeField = (activeField + step + fieldItems.length) % fieldItems.length;
    markActive(el.builderFields, el.builderSearch, activeField, "builder-field-");
  } else if (e.key === "Enter") {
    e.preventDefault();
    if (open && activeField >= 0) {
      chooseField(fieldEntry(fieldItems[activeField]));
    }
  } else if (e.key === "Escape" && !el.builderFields.classList.contains("hidden")) {
    e.preventDefault();
    e.stopPropagation(); // closes the list, not the dialog
    hideFields();
  }
});

/**
 * @param {{name: string, type: string, desc: string}} entry @param {string} [value]
 */
function chooseField(entry, value) {
  window.clearTimeout(searchTimer);
  searchSeq++;
  hideFields();
  el.builderSearch.value = entry.name;
  setField(entry);
  const ops = lib.builderOperators(entry.type);
  const wanted = value !== undefined ? "==" : ops.some((o) => o.op === "==") ? "==" : "present";
  el.builderOp.value = ops.some((o) => o.op === wanted) ? wanted : ops[0].op;
  el.builderValue.value = value ?? "";
  onOpChange();
  clearValues();
  if (entry.type !== "protocol" && entry.type !== "FT_NONE" && entry.type !== "FT_PROTOCOL") {
    void loadValues(entry.name);
  }
  (el.builderValue.hasAttribute("disabled") ? el.builderOp : el.builderValue).focus();
}

/** @param {{name: string, type: string, desc: string} | null} entry */
function setField(entry) {
  field = entry;
  if (!entry) {
    el.builderField.textContent = "Pick a field to filter on.";
    el.builderOp.replaceChildren();
    el.builderOp.setAttribute("disabled", "");
    el.builderValue.setAttribute("disabled", "");
    update();
    return;
  }
  const type = entry.type === "protocol" ? "protocol" : lib.friendlyType(entry.type);
  el.builderField.textContent = `${entry.desc ? `${entry.desc} (${entry.name})` : entry.name}: ${type}`;
  el.builderOp.replaceChildren(
    ...lib.builderOperators(entry.type).map((/** @type {any} */ o) => {
      const option = document.createElement("option");
      option.value = o.op;
      option.textContent = o.label;
      return option;
    }),
  );
  el.builderOp.removeAttribute("disabled");
}

function onOpChange() {
  const op = lib
    .builderOperators(field?.type ?? "")
    .find((/** @type {any} */ o) => o.op === el.builderOp.value);
  el.builderValue.toggleAttribute("disabled", !op?.value);
  update();
}

el.builderOp.addEventListener("change", onOpChange);
el.builderValue.addEventListener("input", update);
el.builderCombine.addEventListener("change", update);

/* ------------------------------------------------------------- values seen */

/** @param {string} name */
async function loadValues(name) {
  stopValues();
  const req = rpc("field_values", { field: name });
  valuesRequest = req.id;
  el.builderValuesHead.classList.remove("hidden");
  el.builderValuesStatus.textContent = "Reading the values seen in this capture…";
  el.builderValuesStop.classList.remove("hidden");
  try {
    const res = await req.promise;
    if (valuesRequest !== req.id || field?.name !== name) {
      return;
    }
    showValues(res);
  } catch (err) {
    if (valuesRequest !== req.id) {
      return;
    }
    const e = /** @type {any} */ (err);
    el.builderValuesStatus.textContent =
      e?.code === CANCELLED
        ? "Stopped reading the values."
        : `The values could not be read: ${e?.message ?? e}`;
  } finally {
    if (valuesRequest === req.id) {
      valuesRequest = null;
      el.builderValuesStop.classList.add("hidden");
    }
  }
}

function stopValues() {
  if (valuesRequest !== null) {
    cancelRpc(valuesRequest);
    valuesRequest = null;
  }
}

el.builderValuesStop.addEventListener("click", () => {
  if (valuesRequest !== null) {
    cancelRpc(valuesRequest);
  }
});

function clearValues() {
  valueItems = [];
  activeValue = -1;
  el.builderValues.replaceChildren();
  el.builderValues.classList.add("hidden");
  el.builderValues.removeAttribute("tabindex");
  el.builderValuesHead.classList.add("hidden");
}

/** @param {{values: {value: string, count: number}[], packets: number, distinct: number, more: number}} res */
function showValues(res) {
  valueItems = res.values;
  activeValue = -1;
  if (!res.packets) {
    el.builderValuesStatus.textContent = "No packet in this capture has this field.";
    return;
  }
  const shown =
    res.values.length < res.distinct ? `, the ${res.values.length} most frequent shown` : "";
  el.builderValuesStatus.textContent = `${res.distinct.toLocaleString()} value${res.distinct === 1 ? "" : "s"} in ${res.packets.toLocaleString()} packet${res.packets === 1 ? "" : "s"}${shown}. Pick one:`;
  el.builderValues.replaceChildren(
    ...res.values.map((v, i) => {
      const row = document.createElement("div");
      row.id = `builder-value-${i}`;
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", "false");
      const value = document.createElement("span");
      value.textContent = v.value;
      const count = document.createElement("span");
      count.className = "builder-desc";
      count.textContent = `${v.count.toLocaleString()} packet${v.count === 1 ? "" : "s"}`;
      row.append(value, count);
      row.addEventListener("click", () => pickValue(i));
      return row;
    }),
  );
  el.builderValues.classList.remove("hidden");
  el.builderValues.tabIndex = 0;
}

/** @param {number} i */
function pickValue(i) {
  activeValue = i;
  markActive(el.builderValues, el.builderValues, i, "builder-value-");
  const ops = lib.builderOperators(field?.type ?? "");
  const op = ops.find((/** @type {any} */ o) => o.op === el.builderOp.value);
  if (!op?.value) {
    el.builderOp.value = "==";
    onOpChange();
  }
  el.builderValue.value = valueItems[i].value;
  update();
}

el.builderValues.addEventListener("keydown", (e) => {
  if (!valueItems.length) {
    return;
  }
  const last = valueItems.length - 1;
  const moves = /** @type {Record<string, number>} */ ({
    ArrowDown: Math.min(activeValue + 1, last),
    ArrowUp: Math.max(activeValue - 1, 0),
    Home: 0,
    End: last,
  });
  if (e.key in moves) {
    e.preventDefault();
    pickValue(moves[e.key]);
  }
});

/* ------------------------------------------------------------- preview, apply */

function update() {
  const term = field
    ? lib.builderTerm(field.name, field.type, el.builderOp.value, el.builderValue.value)
    : null;
  expr = term ? lib.combineFilter(el.filterInput.value, term, el.builderCombine.value) : "";
  el.builderPreview.textContent = expr || "—";
  valid = false;
  setButtons();
  el.builderError.textContent = "";
  el.builderError.classList.remove("invalid");
  window.clearTimeout(validateTimer);
  if (expr) {
    validateTimer = window.setTimeout(validate, 200);
  }
}

async function validate() {
  const seq = ++validateSeq;
  const checking = expr;
  try {
    const res = await rpc("validate_filter", { expr: checking }).promise;
    if (seq !== validateSeq || checking !== expr) {
      return;
    }
    valid = res.valid;
    el.builderError.textContent = res.valid ? "" : res.error;
    el.builderError.classList.toggle("invalid", !res.valid);
  } catch {
    valid = true; // (tshark checks it again when applied)
  }
  setButtons();
}

function setButtons() {
  el.builderApply.toggleAttribute("disabled", !expr || !valid);
  el.builderInsert.toggleAttribute("disabled", !expr);
}

el.builderApply.addEventListener("click", () => {
  if (!expr || !valid) {
    return;
  }
  const filter = expr;
  el.filterInput.value = filter;
  closeFilterBuilder();
  void applyFilter(filter);
});

el.builderInsert.addEventListener("click", () => {
  if (!expr) {
    return;
  }
  el.filterInput.value = expr;
  closeFilterBuilder();
  validateSoon();
  el.filterInput.focus();
});

el.builderCancel.addEventListener("click", closeFilterBuilder);
el.builderClose.addEventListener("click", closeFilterBuilder);
el.filterBuild.addEventListener("click", () => openFilterBuilder());
el.builder.addEventListener("click", (e) => {
  if (e.target === el.builder) {
    closeFilterBuilder(); // a click on the backdrop
  }
});

el.builder.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    closeFilterBuilder();
    return;
  }
  if (
    e.key === "Enter" &&
    e.target === el.builderValue &&
    !el.builderApply.hasAttribute("disabled")
  ) {
    e.preventDefault();
    el.builderApply.click();
    return;
  }
  if (e.key === "Tab") {
    // Keep the focus inside the dialog.
    const focusable = /** @type {HTMLElement[]} */ (
      [...el.builder.querySelectorAll("button, input, select, [tabindex='0']")].filter(
        (n) => !n.hasAttribute("disabled") && /** @type {HTMLElement} */ (n).offsetParent !== null,
      )
    );
    if (!focusable.length) {
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
  e.stopPropagation(); // the viewer's own keys (F3, Ctrl+F…) don't fire behind the dialog
});
