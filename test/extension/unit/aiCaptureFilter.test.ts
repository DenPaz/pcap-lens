import * as assert from "node:assert/strict";
import {
  buildCaptureFilterPrompt,
  buildCaptureRetryPrompt,
  suggestCaptureFilters,
} from "../../../src/aiCaptureFilter";
import type { ChatTurn } from "../../../src/aiFilter";

suite("aiCaptureFilter", () => {
  test("the prompt asks for BPF, not display filters, with the request, filter and interfaces", () => {
    const prompt = buildCaptureFilterPrompt({
      request: "only HTTPS\nto the web server",
      currentFilter: "not arp",
      interfaces: [{ name: "eth0" }, { name: "lo", loopback: true }],
    });
    assert.match(prompt, /pcap-filter \(BPF\)/);
    assert.match(prompt, /NOT Wireshark display filters/);
    assert.match(prompt, /Request: only HTTPS to the web server$/m);
    assert.match(prompt, /Current capture filter: not arp$/m);
    assert.match(prompt, /Capturing on: eth0, lo \(loopback\)$/m);
    assert.match(
      buildCaptureFilterPrompt({ request: "dns", currentFilter: "", interfaces: [] }),
      /Current capture filter: \(none\)\nCapturing on: \(unknown\)$/,
    );
  });

  test("the retry names dumpcap's errors, or asks for JSON again", () => {
    const retry = buildCaptureRetryPrompt([
      { filter: "tcp.port == 443", error: "syntax error\nin filter expression" },
    ]);
    assert.match(retry, /dumpcap could not compile/);
    assert.match(retry, /- tcp\.port == 443: syntax error in filter expression/);
    assert.match(buildCaptureRetryPrompt([]), /JSON only/);
  });

  test("display-filter answers are rejected by dumpcap and retried once with its errors", async () => {
    const asked: ChatTurn[][] = [];
    const answers = [
      '[{"filter": "tcp.port == 443", "explanation": "HTTPS"}]',
      '```json\n[{"filter": "tcp port 443", "explanation": "HTTPS"}]\n```',
    ];
    const res = await suggestCaptureFilters(
      {
        ask: async (turns) => {
          asked.push([...turns]);
          return answers[asked.length - 1];
        },
        validate: async (f) => (f.includes("==") ? "syntax error" : undefined),
      },
      { request: "https", currentFilter: "", interfaces: [{ name: "eth0" }] },
    );
    assert.deepEqual(res.suggestions, [{ filter: "tcp port 443", explanation: "HTTPS" }]);
    assert.deepEqual(res.rejected, [{ filter: "tcp.port == 443", error: "syntax error" }]);
    assert.equal(asked.length, 2);
    assert.match(asked[1][2].content, /dumpcap could not compile/);
  });
});
