import * as assert from "node:assert/strict";
import {
  COMPARE_LIMITS,
  CaptureDiff,
  buildComparePrompt,
  compareQuery,
  parseCompareArgs,
  shrinkDiff,
} from "../../../src/aiCompare";
import { STATISTICS_CONSENT } from "../../../src/aiConsent";

/** A diff shaped like the backend's `compare_profiles` result (office-before → office-after). */
function officeDiff(flows = 5): CaptureDiff {
  return {
    before: { name: "office-before.pcap", packets: 96, bytes: 9600, seconds: 10 },
    after: { name: "office-after.pcap", packets: 103, bytes: 10300, seconds: 10 },
    checks: {
      changed: [
        {
          id: "tcp_resets",
          check: "TCP resets (RST)",
          filter: "tcp.flags.reset == 1",
          before: 0,
          after: 5,
          beforePer1000: 0,
          afterPer1000: 48.5,
          firstPacketAfter: 61,
        },
      ],
      unchangedNonZero: ["dns_queries"],
      notCompared: [],
    },
    protocols: { new: [], gone: [], changed: [] },
    flows: {
      new: Array.from({ length: flows }, (_, i) => ({
        flow: `tcp 10.0.0.66 → 10.0.0.80:${1000 + i}`,
        after: { connections: 1, packets: 2, bytes: 120 },
      })),
      gone: [],
      changed: [],
    },
    endpoints: { new: [{ address: "10.0.0.66" }], gone: [], changed: [] },
    expert: { new: [{ summary: "Connection reset (RST)", after: 5 }], gone: [] },
  };
}

suite("aiCompare", () => {
  test("the prompt holds both names, the open capture, the question and the diff", () => {
    const prompt = buildComparePrompt({
      question: "  why is   the CRM slow? ",
      diff: officeDiff(),
      open: "after",
    });
    assert.match(prompt, /## Before: office-before\.pcap/);
    assert.match(prompt, /## After: office-after\.pcap/);
    assert.match(prompt, /the after capture \(office-after\.pcap\)/);
    assert.match(prompt, /Question: why is the CRM slow\?/);
    assert.match(prompt, /```filter/);
    assert.match(prompt, /untrusted/);
    assert.match(prompt, /never packet\s+contents/);
    const json = JSON.parse(prompt.slice(prompt.indexOf("## Differences (JSON)\n") + 22));
    assert.equal(json.checks.changed[0].id, "tcp_resets");
    assert.equal(json.flows.new.length, 5);
    // No question: a default one.
    const plain = buildComparePrompt({ question: "", diff: officeDiff(), open: "before" });
    assert.match(plain, /Question: what changed/);
    assert.match(plain, /the before capture \(office-before\.pcap\)/);
  });

  test("lists are cut to maxItems, and halved until the prompt fits", () => {
    const cut = shrinkDiff(officeDiff(40), 15);
    const flows = cut.flows as { new: unknown[]; more: Record<string, number> };
    assert.equal(flows.new.length, 15);
    assert.deepEqual(flows.more, { new: 25 });
    // Lists that fit and plain values are kept as they are.
    assert.deepEqual(cut.endpoints, officeDiff(40).endpoints);
    assert.equal(cut.before.name, "office-before.pcap");

    const full = buildComparePrompt({ question: "", diff: officeDiff(40), open: "after" });
    assert.equal(
      JSON.parse(full.slice(full.indexOf("{"))).flows.new.length,
      COMPARE_LIMITS.maxItems,
    );
    const small = buildComparePrompt(
      { question: "", diff: officeDiff(40), open: "after" },
      { maxItems: 15, maxPromptChars: 2600 },
    );
    assert.ok(small.length <= 2600);
    const n = JSON.parse(small.slice(small.indexOf("{"))).flows.new.length;
    assert.ok(n < 15 && n >= 1, `${n} flows`);
    // Nothing fits: a hard cut that says so.
    const tiny = buildComparePrompt(
      { question: "", diff: officeDiff(40), open: "after" },
      { maxItems: 15, maxPromptChars: 500 },
    );
    assert.ok(tiny.length <= 500);
    assert.match(tiny, /\[cut: the data is too long\]$/);
  });

  test("chat arguments: a saved comparison, a path or only a question", () => {
    assert.deepEqual(parseCompareArgs("#3 why more resets?"), {
      ref: 3,
      question: "why more resets?",
    });
    assert.deepEqual(parseCompareArgs("baseline.pcapng what changed"), {
      path: "baseline.pcapng",
      question: "what changed",
    });
    assert.deepEqual(parseCompareArgs("captures/monday what changed"), {
      path: "captures/monday",
      question: "what changed",
    });
    assert.deepEqual(parseCompareArgs('"my capture.pcap" dns?'), {
      path: "my capture.pcap",
      question: "dns?",
    });
    assert.deepEqual(parseCompareArgs("'C:\\caps\\a b.pcap'"), {
      path: "C:\\caps\\a b.pcap",
      question: "",
    });
    assert.deepEqual(parseCompareArgs("what changed?"), { question: "what changed?" });
    assert.deepEqual(parseCompareArgs(""), { question: "" });
    assert.equal(compareQuery(7), "@pcap /compare #7");
  });

  test("the statistics consent names comparisons and their limit", () => {
    assert.match(STATISTICS_CONSENT, /comparing captures/);
    assert.match(
      STATISTICS_CONSENT,
      new RegExp(`up to ${COMPARE_LIMITS.maxItems} protocols, flows`),
    );
  });
});
