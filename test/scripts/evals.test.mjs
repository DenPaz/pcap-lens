import * as assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import {
  caseProblems,
  grade,
  sentences,
  summaryTable,
  textBlocks,
  triageBlocks,
} from "../../scripts/evals/grade.mjs";

const read = (name) => JSON.parse(readFileSync(new URL(`../evals/${name}`, import.meta.url)));
const { cases } = read("cases.json");
const canned = read("canned.json");

const blocksFor = (c, answer) => (c.kind === "triage" ? triageBlocks(answer) : textBlocks(answer));

suite("evals: cases and grader", () => {
  test("the cases are well-formed and their captures exist", () => {
    assert.deepEqual(caseProblems(cases), []);
    for (const c of cases) {
      for (const capture of c.captures ?? [c.capture]) {
        assert.ok(
          existsSync(new URL(`../fixtures/${capture}`, import.meta.url)),
          `${c.id}: ${capture}`,
        );
      }
    }
  });

  test("every case's good canned answer passes and its bad one fails for the named reasons", () => {
    for (const c of cases) {
      const answers = canned[c.id];
      assert.ok(answers, `${c.id} has canned answers`);
      const good = grade(c, blocksFor(c, answers.good));
      assert.ok(good.passed, `${c.id} good: ${JSON.stringify(good)}`);
      assert.equal(good.score, 1, c.id);
      const bad = grade(c, blocksFor(c, answers.bad));
      assert.equal(bad.passed, false, c.id);
      const reasons = new Set([...bad.missed, ...bad.claims.map((x) => x.id)]);
      assert.deepEqual([...reasons].sort(), [...answers.fails].sort(), c.id);
    }
  });

  test("negated sentences don't count as claims", () => {
    const c = {
      id: "t",
      kind: "summary",
      capture: "x",
      expect: [],
      forbid: [{ id: "scan", label: "scan", any: ["\\bscan"] }],
    };
    for (const text of [
      "There is no scan.",
      "Nothing looks like a scan.",
      "This isn't a scan.",
      "I found no evidence of a port scan.",
    ]) {
      assert.equal(grade(c, textBlocks(text)).passed, true, text);
    }
    const said = grade(c, textBlocks("Clean traffic. 10.0.0.66 runs a scan!"));
    assert.deepEqual(said.claims, [{ id: "scan", sentence: "10.0.0.66 runs a scan!" }]);
  });

  test("an expected finding must sit in one block, with all of `all`", () => {
    const c = {
      id: "t",
      kind: "summary",
      capture: "x",
      expect: [{ id: "scan", label: "scan", all: ["10\\.0\\.0\\.66"], any: ["scan"] }],
    };
    assert.equal(grade(c, textBlocks("10.0.0.66 scans 10.0.0.80.")).score, 1);
    // The host and the word in different paragraphs: not found.
    const apart = grade(c, textBlocks("10.0.0.66 is busy.\n\nThere is a scan."));
    assert.deepEqual([apart.score, apart.missed], [0, ["scan"]]);
    // List items are blocks too.
    assert.deepEqual(textBlocks("Intro:\n- one\n- two\n## Head\nthree").length, 4);
  });

  test('within: "sentence" needs the words in one sentence', () => {
    const c = {
      id: "t",
      kind: "summary",
      capture: "x",
      expect: [{ id: "link", label: "l", all: ["reset"], any: ["scan"], within: "sentence" }],
    };
    assert.equal(grade(c, textBlocks("The resets are the scan's answers.")).score, 1);
    // Same paragraph, different sentences: not linked.
    const apart = grade(c, textBlocks("There were resets. The port scan is worrying."));
    assert.deepEqual([apart.score, apart.missed], [0, ["link"]]);
  });

  test("triage findings: a check id counts, severities are checked, maxSeverity caps", () => {
    const c = {
      id: "t",
      kind: "triage",
      capture: "x",
      expect: [
        { id: "resets", label: "resets", check: ["tcp_resets"], any: ["reset"] },
        { id: "creds", label: "creds", any: ["password"], severity: ["high"] },
      ],
      maxSeverity: "medium",
    };
    const report = {
      summary: "s",
      findings: [
        { severity: "low", title: "Odd TCP", detail: "x", check: "tcp_resets" },
        { severity: "medium", title: "Passwords", detail: "in clear" },
      ],
    };
    const r = grade(c, triageBlocks(report));
    assert.deepEqual(r.found, ["resets"]);
    assert.deepEqual(r.severity, [{ id: "creds", want: ["high"], got: ["medium"] }]);
    assert.equal(r.passed, false);
    const high = grade(
      c,
      triageBlocks({ ...report, findings: [{ ...report.findings[1], severity: "high" }] }),
    );
    assert.deepEqual(
      high.claims.map((x) => x.id),
      ["severity"],
    );
  });

  test("caseProblems names what's wrong", () => {
    const problems = caseProblems([
      { id: "a", kind: "triage", capture: "x", expect: [{ id: "e", label: "e", any: ["("] }] },
      { id: "a", kind: "nope" },
      { id: "c", kind: "compare", captures: ["x"], forbid: [{ id: "f", label: "f", all: ["x"] }] },
      {
        id: "d",
        kind: "summary",
        capture: "x",
        maxSeverity: "huge",
        expect: [
          { id: "e", check: ["x"], severity: ["urgent"] },
          { id: "w", label: "w", any: ["x"], within: "word" },
        ],
      },
    ]);
    for (const want of [
      /^a\/e: Invalid regular expression/,
      /^a: duplicate id/,
      /^a: kind nope/,
      /^a: capture\(s\) missing/,
      /^c: capture\(s\) missing/,
      /^c\/f: forbid needs any/,
      /^d: maxSeverity huge/,
      /^d\/e: no label/,
      /^d\/e: check outside triage/,
      /^d\/e: severity urgent/,
      /^d\/w: within word/,
    ]) {
      assert.ok(
        problems.some((p) => want.test(p)),
        `${want} in ${problems.join(" | ")}`,
      );
    }
  });

  test("sentences and the summary table", () => {
    assert.deepEqual(sentences("One. Two!\nThree? four"), ["One.", "Two!", "Three?", "four"]);
    const table = summaryTable([
      { id: "a", passed: true, score: 1, missed: [], claims: [] },
      {
        id: "b",
        passed: false,
        score: 0.5,
        missed: ["x"],
        claims: [{ id: "y" }],
        filters: { cited: ["f"], invalid: ["f"] },
      },
      { id: "c", passed: false, score: 0, missed: [], claims: [], error: "no key" },
    ]);
    assert.match(table, /^PASS {2}a {2}100%$/m);
    assert.match(
      table,
      /^FAIL {2}b {2}50% {2}· {2}missed: x {2}· {2}unsupported: y {2}· {2}invalid filters: 1$/m,
    );
    assert.match(table, /error: no key/);
    assert.match(table, /1\/3 passed$/);
  });
});
