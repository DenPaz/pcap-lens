// @ts-check
/**
 * The filter bar's text, drawn behind its input: fields, operators,
 * functions, values and strings in their own colours, and the part tshark
 * refused underlined (validate_filter's or set_filter's `span`). The input's
 * own text is transparent (its caret, selection and placeholder are not), so
 * what shows is this copy, kept on the same pixels: same font and padding,
 * and moved with the input's horizontal scroll. Ask-AI mode shows the input's
 * own text (a description, not a filter).
 */

import { el, lib } from "./core.js";

/** The span tshark pointed at, and the input's text it belongs to. */
/** @type {[number, number] | null} */
let span = null;
let spanText = "";

/** Move the copy with the input's horizontal scroll. */
function follow() {
  el.filterPaint.style.transform = `translateX(${-el.filterInput.scrollLeft}px)`;
}

/** Draw the input's text again (a changed text drops the old span). */
export function paintFilter() {
  const value = el.filterInput.value;
  if (span && spanText !== value) {
    span = null;
  }
  el.filterPaint.replaceChildren(
    ...lib
      .filterSegments(value, span)
      .map((/** @type {{text: string, kind: string | null, error: boolean}} */ piece) => {
        const node = document.createElement("span");
        node.textContent = piece.text;
        if (piece.kind) {
          node.className = `tok-${piece.kind}`;
        }
        if (piece.error) {
          node.classList.add("tok-error");
        }
        return node;
      }),
  );
  follow();
}

/**
 * Underline what tshark refused in the filter it checked, `expr` (the
 * input's text trimmed; nothing when the input holds something else now),
 * or nothing (`null`).
 * @param {unknown} where [start, end) in `expr`
 * @param {string} [expr]
 */
export function setFilterSpan(where, expr = "") {
  const value = el.filterInput.value;
  const valid =
    Array.isArray(where) &&
    where.length === 2 &&
    where.every((n) => Number.isInteger(n) && n >= 0) &&
    where[0] <= where[1] &&
    where[1] <= expr.length &&
    value.trim() === expr;
  if (valid) {
    const lead = value.length - value.trimStart().length;
    span = [where[0] + lead, where[1] + lead];
    spanText = value;
  } else {
    span = null;
  }
  paintFilter();
}

// Every way the text changes: typing, and the code that sets `value`
// (history, suggestions, the builder, the host's applyFilter…).
const native = /** @type {PropertyDescriptor} */ (
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")
);
// (Through `any`: defineProperty's type assertion would narrow `el`.)
Object.defineProperty(/** @type {any} */ (el.filterInput), "value", {
  configurable: true,
  get() {
    return native.get?.call(this);
  },
  set(v) {
    native.set?.call(this, v);
    paintFilter();
  },
});
el.filterInput.addEventListener("input", paintFilter);
el.filterInput.addEventListener("scroll", follow);
// (Moving the caret can scroll the text without a scroll event in some engines.)
for (const type of ["keydown", "keyup", "mouseup", "select", "focus", "blur"]) {
  el.filterInput.addEventListener(type, () => requestAnimationFrame(follow));
}
new ResizeObserver(() => follow()).observe(el.filterInput);
// The validity classes (set in several places) give aria-invalid, and a
// filter no longer invalid has nothing underlined.
new MutationObserver(() => {
  const invalid = el.filterInput.classList.contains("invalid");
  if (invalid) {
    el.filterInput.setAttribute("aria-invalid", "true");
  } else {
    el.filterInput.removeAttribute("aria-invalid");
  }
  if (!invalid && span) {
    span = null;
    paintFilter();
  }
}).observe(el.filterInput, { attributes: true, attributeFilter: ["class"] });
el.filterText.classList.add("painted");
paintFilter();
