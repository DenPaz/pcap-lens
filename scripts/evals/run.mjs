#!/usr/bin/env node
/**
 * Runs the answer-quality cases (test/evals/cases.json) by hand: for each
 * case it opens the capture(s) in a real backend, builds the prompt with the
 * extension's own code (aiTriage/aiSummary/aiCompare, compiled to out/), with
 * address stand-ins as the extension sends them, asks a model, restores the
 * answer, checks its display filters with tshark and grades it
 * (scripts/evals/grade.mjs). Not part of CI: it costs model calls.
 *
 *   pnpm run compile
 *   node scripts/evals/run.mjs                       # every case, Claude (ANTHROPIC_API_KEY or `ant auth login`)
 *   node scripts/evals/run.mjs --case office-compare --repeat 3 --model claude-sonnet-5-5
 *   node scripts/evals/run.mjs --prompts /tmp/prompts    # only write the prompts (paste them into any model)
 *   node scripts/evals/run.mjs --answers /tmp/answers    # grade saved answers, <case>.md
 *
 * Options: --case <id> (repeatable), --model <id> (default claude-opus-5-5),
 * --effort low|medium|high|xhigh|max, --repeat <n>, --no-stand-ins,
 * --save <dir> (each prompt and answer), --out <file.json> (the results).
 * Exit code 1 when a case fails.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { grade, summaryTable, textBlocks, triageBlocks } from "./grade.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);
const out = (name) => require(path.join(ROOT, "out", "src", name));

// `pnpm run evals -- --case x` passes the "--" on.
const argv = process.argv.slice(2);
const { values: opts } = parseArgs({
  args: argv[0] === "--" ? argv.slice(1) : argv,
  options: {
    case: { type: "string", multiple: true },
    model: { type: "string", default: "claude-opus-5-5" },
    effort: { type: "string" },
    repeat: { type: "string", default: "1" },
    "no-stand-ins": { type: "boolean", default: false },
    prompts: { type: "string" },
    answers: { type: "string" },
    save: { type: "string" },
    out: { type: "string" },
  },
});

let deps;
try {
  deps = {
    triage: out("aiTriage.js"),
    summary: out("aiSummary.js"),
    compare: out("aiCompare.js"),
    privacy: out("aiPrivacy.js"),
    explain: out("aiExplain.js"),
  };
} catch {
  console.error("Build first: pnpm run compile (the runner uses out/src).");
  process.exit(2);
}
const { startBackend, FIXTURES } = require(path.join(ROOT, "test/webview/harness.js"));
const backendDeps = out("backendClient.js");

const { cases } = JSON.parse(readFileSync(path.join(ROOT, "test/evals/cases.json"), "utf8"));
const chosen = opts.case?.length ? cases.filter((c) => opts.case.includes(c.id)) : cases;
if (!chosen.length) {
  console.error(`No such case: ${opts.case.join(", ")}`);
  process.exit(2);
}

/** A backend with `capture` opened as the MCP server opens it (names off). */
async function openCapture(capture) {
  const client = await startBackend(backendDeps);
  await client.request("open", { path: path.join(FIXTURES, capture), names: {} }, { timeoutMs: 0 });
  return client;
}

const requester = (client) => (method, params, options) => client.request(method, params, options);

/** The prompt (and what grading a triage needs) for one case. */
async function preparePrompt(c, clients) {
  if (c.kind === "triage") {
    const input = await deps.triage.gatherTriage(requester(clients[0]), "");
    return { prompt: deps.triage.buildTriagePrompt(input), input };
  }
  if (c.kind === "summary") {
    const input = await deps.summary.gatherSummary(requester(clients[0]), {
      question: "",
      currentFilter: "",
    });
    return { prompt: deps.summary.buildSummaryPrompt(input) };
  }
  const [before, after] = await Promise.all(
    clients.map((cl) => cl.request("capture_profile", {}, { timeoutMs: 0 })),
  );
  const openIndex = c.open === "before" ? 0 : 1;
  const diff = await clients[openIndex].request("compare_profiles", {
    before,
    after,
    names: c.captures,
  });
  return { prompt: deps.compare.buildComparePrompt({ question: "", diff, open: c.open }) };
}

let anthropic;
/** One model turn: the messages as the extension sends them (stand-ins masked in, restored out). */
async function ask(turns, masker) {
  if (!anthropic) {
    const { default: Anthropic } = await import("@anthropic-ai/sdk");
    anthropic = new Anthropic();
  }
  const messages = turns.map((t, i) => {
    const content = masker.mask(t.content);
    return {
      role: t.role,
      content: i === 0 ? deps.privacy.withStandInNote(masker, content) : content,
    };
  });
  const response = await anthropic.messages.create({
    model: opts.model,
    max_tokens: 16000,
    messages,
    ...(opts.effort ? { output_config: { effort: opts.effort } } : {}),
  });
  if (response.stop_reason === "refusal") {
    throw new Error(`the model declined (${response.stop_details?.category ?? "no category"})`);
  }
  const text = response.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
  return masker.restore(text);
}

async function invalidFilters(client, filters) {
  const invalid = [];
  for (const expr of filters) {
    const r = await client.request("validate_filter", { expr });
    if (!r.valid) invalid.push(expr);
  }
  return invalid;
}

/** Run one case once: its result for the grader, plus the prompt and answer. */
async function runCase(c, run) {
  const clients = [];
  try {
    for (const capture of c.captures ?? [c.capture]) {
      clients.push(await openCapture(capture));
    }
    const open = clients[c.kind === "compare" && c.open === "before" ? 0 : clients.length - 1];
    const { prompt, input } = await preparePrompt(c, clients);
    const masker = new deps.privacy.AddressMasker(!opts["no-stand-ins"]);
    const tag = opts.repeat === "1" ? c.id : `${c.id}.${run}`;
    if (opts.prompts) {
      mkdirSync(opts.prompts, { recursive: true });
      const sent = deps.privacy.withStandInNote(masker, masker.mask(prompt));
      writeFileSync(path.join(opts.prompts, `${c.id}.txt`), sent);
      return undefined;
    }
    let answer;
    const turns = [{ role: "user", content: prompt }];
    if (opts.answers) {
      answer = readFileSync(path.join(opts.answers, `${c.id}.md`), "utf8");
    } else {
      answer = await ask(turns, masker);
    }
    let blocks;
    let cited;
    if (c.kind === "triage") {
      let report = deps.triage.parseTriage(answer, input);
      if (!report && !opts.answers) {
        turns.push(
          { role: "assistant", content: answer },
          { role: "user", content: deps.triage.TRIAGE_RETRY },
        );
        answer = await ask(turns, masker);
        report = deps.triage.parseTriage(answer, input);
      }
      if (!report) {
        throw new Error("the answer isn't the findings JSON asked for");
      }
      blocks = triageBlocks(report);
      const checkFilters = new Set(input.checks.map((k) => k.filter));
      cited = [
        ...new Set(
          report.findings.flatMap((f) =>
            f.filter && !checkFilters.has(f.filter) ? [f.filter] : [],
          ),
        ),
      ];
    } else {
      blocks = textBlocks(answer);
      cited = deps.explain.extractFilters(answer);
    }
    if (opts.save) {
      mkdirSync(opts.save, { recursive: true });
      writeFileSync(path.join(opts.save, `${tag}.prompt.txt`), prompt);
      writeFileSync(path.join(opts.save, `${tag}.answer.md`), answer);
    }
    return grade(c, blocks, { cited, invalid: await invalidFilters(open, cited) });
  } catch (err) {
    return {
      id: c.id,
      passed: false,
      score: 0,
      found: [],
      missed: [],
      claims: [],
      error: err?.message ?? String(err),
    };
  } finally {
    await Promise.all(clients.map((cl) => cl.dispose()));
  }
}

const results = [];
const repeat = Math.max(1, Number(opts.repeat) || 1);
for (const c of chosen) {
  for (let run = 1; run <= repeat; run++) {
    process.stderr.write(`${c.id}${repeat > 1 ? ` (${run}/${repeat})` : ""}…\n`);
    const r = await runCase(c, run);
    if (r) results.push({ ...r, run, model: opts.answers ? "saved answers" : opts.model });
  }
}
if (opts.prompts) {
  console.log(`Prompts written to ${opts.prompts}`);
  process.exit(0);
}
console.log(summaryTable(results));
for (const r of results) {
  for (const claim of r.claims)
    console.log(`  ${r.id}: unsupported "${claim.id}": ${claim.sentence}`);
  for (const s of r.severity ?? []) {
    console.log(`  ${r.id}: ${s.id} rated ${s.got.join("/") || "?"}, expected ${s.want.join("/")}`);
  }
}
if (opts.out) {
  writeFileSync(opts.out, `${JSON.stringify({ model: opts.model, results }, null, 2)}\n`);
}
process.exit(results.every((r) => r.passed) ? 0 : 1);
