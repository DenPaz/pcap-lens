import * as assert from "node:assert/strict";
import {
  COMPARE_LIMITS,
  CaptureDiff,
  buildComparePrompt,
  compareQuery,
  parseCompareArgs,
  scanFilter,
  scanLines,
  scanNote,
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
    scans: {
      new: [
        {
          kind: "port scan",
          protocol: "tcp",
          client: "10.0.0.66",
          server: "10.0.0.80",
          ports: [22, 23],
          packets: 4,
        },
      ],
      gone: [],
      both: [],
    },
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
    assert.match(prompt, /call them scans/);
    assert.match(
      prompt,
      /## Scans tshark's numbers show\n[\s\S]*?\n- Port scan, only in the after capture: 10\.0\.0\.66 reached 2 TCP ports of 10\.0\.0\.80 \(22, 23\), 4 packets/,
    );
    assert.match(prompt, /"scans":\{"new":\[\{"kind":"port scan"/);
    const json = JSON.parse(prompt.slice(prompt.indexOf("## Differences (JSON)\n") + 22));
    assert.equal(json.checks.changed[0].id, "tcp_resets");
    assert.equal(json.flows.new.length, 5);
    // No question: a default one.
    const plain = buildComparePrompt({ question: "", diff: officeDiff(), open: "before" });
    assert.match(plain, /Question: what changed/);
    assert.match(plain, /the before capture \(office-before\.pcap\)/);
  });

  test("scans in words: sweeps, gone and both, long lists cut, none = no section", () => {
    const servers = Array.from({ length: 10 }, (_, i) => `10.0.1.${i + 1}`);
    const lines = scanLines({
      ...officeDiff(),
      scans: {
        new: [],
        gone: [
          {
            kind: "host sweep",
            protocol: "udp",
            client: "10.0.0.9",
            port: 161,
            servers,
            packets: 20,
          },
        ],
        both: [
          {
            kind: "port scan",
            protocol: "tcp",
            client: "a",
            server: "b",
            ports: [1, 2, 3, 4],
            packets: 8,
          },
        ],
      },
    });
    assert.deepEqual(lines, [
      "- Host sweep, only in the before capture: 10.0.0.9 reached UDP port 161 on 10 servers" +
        " (10.0.1.1, 10.0.1.2, 10.0.1.3, 10.0.1.4, 10.0.1.5, 10.0.1.6, 10.0.1.7, 10.0.1.8, …)," +
        " 20 packets, a few per connection.",
      "- Port scan, in both captures: a reached 4 TCP ports of b (1, 2, 3, 4), 8 packets, a few per connection.",
    ]);
    const noScans: CaptureDiff = { ...officeDiff(), scans: undefined };
    assert.deepEqual(scanLines(noScans), []);
    assert.doesNotMatch(
      buildComparePrompt({ question: "", diff: noScans, open: "after" }),
      /## Scans/,
    );
  });

  test("the scan note shown above the answer, and its filters", () => {
    const note = scanNote(officeDiff());
    assert.equal(
      note.markdown,
      "**Found by tshark**\n\n- Port scan, only in the after capture: 10.0.0.66 reached 2 TCP ports" +
        " of 10.0.0.80 (22, 23), 4 packets, a few per connection.\n\n",
    );
    assert.deepEqual(note.filters, [
      "ip.src == 10.0.0.66 && ip.dst == 10.0.0.80 && tcp.dstport in {22,23}",
    ]);
    assert.deepEqual(scanNote({ ...officeDiff(), scans: undefined }), {
      markdown: "",
      filters: [],
    });
    // Markdown in an address can't format the note.
    const odd = scanNote({
      ...officeDiff(),
      scans: {
        new: [{ kind: "port scan", protocol: "tcp", client: "*a*", server: "b_c", ports: [1] }],
      },
    });
    assert.match(odd.markdown, /\\\*a\\\* reached 1 TCP ports of b\\_c/);
    assert.equal(
      scanFilter({ kind: "host sweep", protocol: "udp", client: "2001:db8::9", port: 161 }),
      "ipv6.src == 2001:db8::9 && udp.dstport == 161",
    );
    const many = Array.from({ length: 51 }, (_, i) => i + 1);
    assert.equal(
      scanFilter({ kind: "port scan", protocol: "tcp", client: "a", server: "b", ports: many }),
      "ip.src == a && ip.dst == b",
    );
    assert.equal(
      scanFilter({ kind: "port scan", protocol: "sctp", client: "a", server: "b" }),
      undefined,
    );
    assert.equal(scanFilter({ kind: "host sweep", protocol: "tcp", client: "a" }), undefined);
  });

  test("lists are cut to maxItems, and halved until the prompt fits", () => {
    const cut = shrinkDiff(officeDiff(40), 15);
    const flows = cut.flows as { new: unknown[]; more: Record<string, number> };
    assert.equal(flows.new.length, 15);
    assert.deepEqual(flows.more, { new: 25 });
    // Lists that fit and plain values are kept as they are.
    assert.deepEqual(cut.endpoints, officeDiff(40).endpoints);
    assert.equal(cut.before.name, "office-before.pcap");
    // Scans seen in both captures are cut like the rest.
    const both = shrinkDiff({ ...officeDiff(), scans: { new: [], gone: [], both: [1, 2, 3] } }, 2);
    assert.deepEqual(both.scans, { new: [], gone: [], both: [1, 2], more: { both: 1 } });

    const full = buildComparePrompt({ question: "", diff: officeDiff(40), open: "after" });
    assert.equal(
      JSON.parse(full.slice(full.indexOf("{"))).flows.new.length,
      COMPARE_LIMITS.maxItems,
    );
    const small = buildComparePrompt(
      { question: "", diff: officeDiff(40), open: "after" },
      { maxItems: 15, maxPromptChars: 3000 },
    );
    assert.ok(small.length <= 3000);
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
