import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  AGENT_MODE,
  AGENT_QUERY_LIMITS,
  AgentAsk,
  agentQuery,
  askInSetting,
} from "../../../src/aiAgentQuery";
import type { ExpertRow } from "../../../src/aiAnomaly";

const ROOT = path.resolve(__dirname, "../../../..");
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
  contributes: {
    languageModelTools: { toolReferenceName: string }[];
    configuration: { properties: Record<string, { default?: unknown; enum?: string[] }> };
  };
};
const REFERENCES = new Set(pkg.contributes.languageModelTools.map((t) => t.toolReferenceName));

const row = (over: Partial<ExpertRow> = {}): ExpertRow => ({
  severity: "Warning",
  group: "Sequence",
  protocol: "TCP",
  summary: "Connection reset to 10.0.0.5 by GET /secret",
  count: 7,
  frames: [4, 9, 15, 21, 30, 44, 51],
  ...over,
});

const ASKS: AgentAsk[] = [
  { kind: "summary", capture: "traces/a.pcapng" },
  { kind: "triage", capture: "a.pcapng" },
  { kind: "compare", capture: "after.pcap", other: "before.pcap", baseline: "other" },
  { kind: "stream", capture: "a.pcapng", stream: 3 },
  { kind: "expert", capture: "a.pcapng", rows: [] },
  { kind: "expert", capture: "a.pcapng", rows: [row()] },
  { kind: "packets", capture: "a.pcapng", frames: [7, 1, 2, 3] },
  { kind: "call", capture: "calls.pcap", call: 2 },
];

suite("aiAgentQuery", () => {
  test("the setting: agent, else @pcap", () => {
    assert.equal(askInSetting("agent"), "agent");
    for (const v of ["pcap", undefined, "", "Agent", 3]) {
      assert.equal(askInSetting(v), "pcap");
    }
    const setting = pkg.contributes.configuration.properties["pcapViewer.ai.askIn"];
    assert.equal(setting.default, "pcap");
    assert.deepEqual(setting.enum, ["pcap", "agent"]);
  });

  test("the agent's mode is its name in the agent file", () => {
    const agent = fs.readFileSync(path.join(ROOT, "agents/pcap-lens.agent.md"), "utf8");
    assert.match(agent, new RegExp(`^name: ${AGENT_MODE}$`, "m"));
  });

  test("every request names the capture and only declared tools, never @pcap", () => {
    for (const ask of ASKS) {
      const q = agentQuery(ask);
      assert.ok(q.includes(`\`${ask.capture}\``), q);
      const refs = [...q.matchAll(/#(\w+)/g)].map((m) => m[1]);
      assert.ok(refs.length, q);
      for (const r of refs) {
        assert.ok(REFERENCES.has(r), `${r} in ${q}`);
      }
      assert.doesNotMatch(q, /@pcap/);
    }
  });

  test("each kind asks the tool that answers it", () => {
    assert.match(agentQuery(ASKS[0]), /#pcapOverview.*#pcapTriage/);
    assert.match(agentQuery(ASKS[1]), /#pcapTriage/);
    assert.match(agentQuery(ASKS[3]), /TCP stream 3 .*#pcapTcpStream/);
    assert.match(agentQuery(ASKS[4]), /#pcapStats \(kind expert\)/);
    assert.match(agentQuery(ASKS[6]), /Packets 1-3 7 .*#pcapPacketDetails/);
    assert.match(
      agentQuery(ASKS[7]),
      /^Explain this call: .* Call 2 of the capture `calls\.pcap`: use #pcapVoipCalls with call 2, then #pcapRtpStream/,
    );
    assert.match(
      agentQuery({ kind: "call", capture: "c", call: 0, heuristic: true }),
      /#pcapVoipCalls with call 0 and heuristic_rtp: true,/,
      "the panel's list found RTP heuristically: so must the tool",
    );
  });

  test("a comparison says which capture is the baseline", () => {
    assert.match(
      agentQuery(ASKS[2]),
      /`before\.pcap` is the baseline and `after\.pcap` the later one.*#pcapCompare.*baseline: "other"/,
    );
    const open = agentQuery({ ...ASKS[2], baseline: "open" } as AgentAsk);
    assert.match(open, /`after\.pcap` is the baseline and `before\.pcap` the later one/);
    assert.match(open, /baseline: "open"/);
  });

  test("expert rows go by severity, group, protocol and packets, never their message", () => {
    const q = agentQuery(ASKS[5]);
    assert.match(q, /^- Warning \(Sequence, TCP\), 7 packets: 4, 9, 15, 21, 30…$/m);
    assert.doesNotMatch(q, /10\.0\.0\.5|secret|reset/i);
    const many = Array.from({ length: AGENT_QUERY_LIMITS.expertRows + 3 }, (_, i) =>
      row({ frames: [i + 1] }),
    );
    const lines = agentQuery({ kind: "expert", capture: "a", rows: many }).split("\n");
    assert.equal(lines.filter((l) => l.startsWith("- Warning")).length, 10);
    assert.ok(lines.includes("- and 3 more entries"));
  });

  test("a question replaces the default one, on one line", () => {
    const q = agentQuery({ kind: "stream", capture: "a", stream: 1, question: "Why\nslow?" });
    assert.match(q, /^Why slow\? TCP stream 1/);
    assert.doesNotMatch(agentQuery(ASKS[3]), /Why slow/);
    assert.match(agentQuery({ kind: "summary", capture: "x`y" }), /`x'y`/);
  });
});
