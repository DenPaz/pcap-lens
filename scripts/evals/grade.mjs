/**
 * Grades an AI answer against an eval case (test/evals/cases.json): which
 * expected findings it names, which claims the data doesn't support it makes,
 * and (triage) the severities it gives. Pure, so the unit tests grade canned
 * answers (test/scripts/evals.test.mjs); scripts/evals/run.mjs grades real ones.
 *
 * An answer is a list of blocks: a triage's summary and each finding (with
 * its severity and check), or a text answer's paragraphs. An expected finding
 * is found when one block matches all of its `all` patterns and one of its
 * `any` (or, for a triage finding, names one of its `check`s), and has one of
 * its `severity` values when it asks for one. A forbidden claim counts when a
 * sentence matches it and holds no negation ("no resets", "nothing suggests a
 * scan" are fine).
 */

export const SEVERITY_ORDER = ["info", "low", "medium", "high"];

const NEGATION = /\b(no|not|none|never|nothing|neither|nor|without|absent|zero)\b|n't\b/i;

const regex = (source) => new RegExp(source, "i");

/** A text answer's blocks: its paragraphs (blank lines, headings and list items split them). */
export function textBlocks(text) {
  return String(text)
    .split(/\n\s*\n|\n(?=\s*(?:#{1,6}\s|[-*+]\s|\d+[.)]\s))/)
    .map((t) => t.trim())
    .filter(Boolean)
    .map((t) => ({ text: t }));
}

/** A triage report's blocks: the summary, then one per finding. */
export function triageBlocks(report) {
  const blocks = report.summary ? [{ text: report.summary }] : [];
  for (const f of report.findings ?? []) {
    blocks.push({
      text: [f.title, f.detail, f.filter].filter(Boolean).join("\n"),
      severity: f.severity,
      check: f.check,
      finding: true,
    });
  }
  return blocks;
}

/** Sentences of a text (for forbidden claims: a negated sentence doesn't claim). */
export function sentences(text) {
  return String(text)
    .split(/(?<=[.!?])\s+|\n+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function blockMatches(block, item) {
  const fromCheck = !!(block.check && item.check?.includes(block.check));
  const all = (item.all ?? []).every((p) => regex(p).test(block.text));
  const any = !item.any?.length || item.any.some((p) => regex(p).test(block.text));
  const patterns = (item.all?.length ?? 0) + (item.any?.length ?? 0) > 0;
  return fromCheck || (patterns && all && any);
}

/**
 * Grade `blocks` against `caseDef`: `{score, passed, found, missed,
 * claims, severity}`. `filters` (optional): `{cited, invalid}` from the
 * runner, reported as is (the host drops invalid filters, so they don't fail
 * a case, but they are worth watching).
 */
export function grade(caseDef, blocks, filters = undefined) {
  const found = [];
  const missed = [];
  const severity = [];
  for (const item of caseDef.expect ?? []) {
    const matching = blocks.filter((b) => blockMatches(b, item));
    if (!matching.length) {
      missed.push(item.id);
      continue;
    }
    if (item.severity && !matching.some((b) => b.severity && item.severity.includes(b.severity))) {
      severity.push({
        id: item.id,
        want: item.severity,
        got: [...new Set(matching.map((b) => b.severity).filter(Boolean))],
      });
      missed.push(item.id);
      continue;
    }
    found.push(item.id);
  }
  const claims = [];
  const text = blocks.map((b) => b.text).join("\n\n");
  for (const item of caseDef.forbid ?? []) {
    const patterns = item.any.map(regex);
    const said = sentences(text).find((s) => !NEGATION.test(s) && patterns.some((p) => p.test(s)));
    if (said) {
      claims.push({ id: item.id, sentence: said });
    }
  }
  if (caseDef.maxSeverity) {
    const max = SEVERITY_ORDER.indexOf(caseDef.maxSeverity);
    for (const b of blocks) {
      if (b.finding && SEVERITY_ORDER.indexOf(b.severity) > max) {
        claims.push({ id: "severity", sentence: `${b.severity}: ${b.text.split("\n")[0]}` });
      }
    }
  }
  const expected = (caseDef.expect ?? []).length;
  const score = expected ? found.length / expected : 1;
  const minScore = caseDef.minScore ?? 1;
  return {
    id: caseDef.id,
    score,
    passed: score >= minScore && !claims.length,
    found,
    missed,
    claims,
    severity,
    ...(filters ? { filters } : {}),
  };
}

/** Problems with the cases file itself: ids, regexes, fields (the unit test asserts none). */
export function caseProblems(cases) {
  const problems = [];
  const ids = new Set();
  for (const c of cases) {
    if (ids.has(c.id)) problems.push(`${c.id}: duplicate id`);
    ids.add(c.id);
    if (!["triage", "summary", "compare"].includes(c.kind))
      problems.push(`${c.id}: kind ${c.kind}`);
    if (c.kind === "compare" ? c.captures?.length !== 2 : !c.capture) {
      problems.push(`${c.id}: capture(s) missing`);
    }
    if (c.maxSeverity && !SEVERITY_ORDER.includes(c.maxSeverity)) {
      problems.push(`${c.id}: maxSeverity ${c.maxSeverity}`);
    }
    const itemIds = new Set();
    for (const item of [...(c.expect ?? []), ...(c.forbid ?? [])]) {
      if (itemIds.has(item.id)) problems.push(`${c.id}: duplicate item ${item.id}`);
      itemIds.add(item.id);
      if (!item.label) problems.push(`${c.id}/${item.id}: no label`);
      for (const p of [...(item.any ?? []), ...(item.all ?? [])]) {
        try {
          regex(p);
        } catch (err) {
          problems.push(`${c.id}/${item.id}: ${err.message}`);
        }
      }
      if (!(item.any?.length || item.all?.length || item.check?.length)) {
        problems.push(`${c.id}/${item.id}: nothing to match`);
      }
      if (item.check && c.kind !== "triage")
        problems.push(`${c.id}/${item.id}: check outside triage`);
      for (const s of item.severity ?? []) {
        if (!SEVERITY_ORDER.includes(s)) problems.push(`${c.id}/${item.id}: severity ${s}`);
      }
    }
    for (const item of c.forbid ?? []) {
      if (!item.any?.length) problems.push(`${c.id}/${item.id}: forbid needs any`);
    }
  }
  return problems;
}

/** The results as a table for the terminal. */
export function summaryTable(results) {
  const lines = results.map((r) => {
    const mark = r.passed ? "PASS" : "FAIL";
    const parts = [`${mark}  ${r.id}  ${Math.round(r.score * 100)}%`];
    if (r.missed.length) parts.push(`missed: ${r.missed.join(", ")}`);
    if (r.claims.length) parts.push(`unsupported: ${r.claims.map((c) => c.id).join(", ")}`);
    if (r.filters?.invalid?.length) parts.push(`invalid filters: ${r.filters.invalid.length}`);
    if (r.error) parts.push(`error: ${r.error}`);
    return parts.join("  ·  ");
  });
  const passed = results.filter((r) => r.passed).length;
  lines.push(`${passed}/${results.length} passed`);
  return lines.join("\n");
}
