import * as assert from "node:assert/strict";
import {
  DISSECTOR_LIMITS,
  DissectorRequest,
  buildDissectorPrompt,
  buildDissectorRetryPrompt,
  extractLua,
  generateDissector,
  luaCode,
  luaProblems,
} from "../../../src/aiDissector";
import type { ChatTurn } from "../../../src/aiFilter";
import { luaDissectorTemplate } from "../../../src/luaTemplate";

const REQ: DissectorRequest = {
  name: "acme",
  description: "ACME Telemetry",
  transport: "udp",
  port: 4242,
  layout: "2-byte magic 0xCAFE, 1-byte type (1 Hello, 2 Data), then the payload",
};
const TEMPLATE = luaDissectorTemplate(REQ);
const GOOD = TEMPLATE;

suite("aiDissector", () => {
  test("the prompt holds the template, the registration and the description", () => {
    const prompt = buildDissectorPrompt(REQ, TEMPLATE);
    assert.ok(prompt.includes(TEMPLATE.trimEnd()));
    assert.match(prompt, /udp\.port 4242/);
    assert.match(prompt, /Protocol: ACME Telemetry \(acme, UDP port 4242\)/);
    assert.ok(prompt.endsWith(REQ.layout));
    assert.match(prompt, /no os, io, require/);
    const long = buildDissectorPrompt({ ...REQ, layout: "x".repeat(10_000) }, TEMPLATE);
    assert.ok(long.endsWith("x".repeat(DISSECTOR_LIMITS.maxRequest)));
    assert.ok(!long.endsWith("x".repeat(DISSECTOR_LIMITS.maxRequest + 1)));
  });

  test("extractLua takes the lua block, else the first block, else Lua-looking text", () => {
    assert.equal(
      extractLua("Here:\n```text\nnope\n```\n```lua\nlocal a = 1\n```\nDone."),
      "local a = 1\n",
    );
    assert.equal(extractLua("```\n-- x\nlocal b\n```"), "-- x\nlocal b\n");
    assert.equal(extractLua("local c = 2"), "local c = 2\n");
    assert.equal(extractLua("I can't help with that."), undefined);
  });

  test("luaCode drops comments and empties strings", () => {
    assert.equal(
      luaCode(
        'local a = "os.execute(\\"x\\")" -- io.open\nlocal b = [[require]] --[==[ dofile ]==] c',
      ),
      'local a = ""  \nlocal b = ""   c',
    );
    assert.equal(luaCode("x = 'it''s'"), "x = ''''");
  });

  test("the template passes; escapes, a missing Proto or registration don't", () => {
    assert.deepEqual(luaProblems(GOOD, "acme"), []);
    assert.deepEqual(luaProblems(GOOD, "other"), ['It doesn\'t define Proto("other", …).']);
    const bad = `${GOOD}\nlocal h = io.popen("id")\nos.execute("rm -rf /")\nlocal f = load(x)\n_G["o".."s"]\nstring.dump(f)`;
    assert.deepEqual(luaProblems(bad, "acme"), [
      "It uses io, os, load, _G, string.dump, which a dissector may not use.",
    ]);
    // Fields, methods and strings with those names are fine.
    const fine = `${GOOD}\nlocal f_os = ProtoField.uint8("acme.os", "OS")\nlocal x = pinfo.cols.io\nbuf:load()`;
    assert.deepEqual(
      luaProblems(fine, "acme").filter((p) => p.includes("may not")),
      [],
    );
    assert.deepEqual(luaProblems(GOOD.replace(/DissectorTable[^\n]*/, ""), "acme"), [
      "It doesn't register the protocol with DissectorTable.get(…):add(…).",
    ]);
    assert.match(luaProblems("x".repeat(DISSECTOR_LIMITS.maxChars + 1), "acme")[0], /longer/);
  });

  test("the retry lists what was wrong", () => {
    assert.equal(
      buildDissectorRetryPrompt(["Lua: acme.lua:3: unexpected\nsymbol"]),
      "The script can't be used yet:\n- Lua: acme.lua:3: unexpected symbol\n" +
        "Reply with the whole corrected script in one ```lua code block.",
    );
  });

  test("a screened-out script is never loaded; tshark's errors go back until it loads", async () => {
    const asked: ChatTurn[][] = [];
    const checked: string[] = [];
    const answers = [
      "```lua\nos.execute('x')\n" + GOOD + "```",
      "```lua\n" + GOOD.replace("return buffer:len()", "return buffer:len(") + "```",
      "```lua\n" + GOOD + "```",
    ];
    const rounds: number[] = [];
    const res = await generateDissector(
      {
        ask: async (turns) => {
          asked.push([...turns]);
          return answers[asked.length - 1];
        },
        check: async (src) => {
          checked.push(src);
          return src.includes("buffer:len(\n") ? ["Lua: acme.lua:30: ')' expected"] : [];
        },
      },
      REQ,
      TEMPLATE,
      (round) => rounds.push(round),
    );
    assert.equal(res.ok, true);
    assert.equal(res.rounds, 3);
    assert.equal(res.source, GOOD);
    assert.deepEqual(rounds, [1, 2, 3]);
    assert.equal(checked.length, 2, "the first answer was screened out, not loaded");
    assert.match(asked[1][2].content, /It uses os/);
    assert.match(asked[2][4].content, /'\)' expected/);
  });

  test("it stops after the last round with the last problems", async () => {
    const res = await generateDissector(
      { ask: async () => "Sorry.", check: async () => [] },
      REQ,
      TEMPLATE,
    );
    assert.deepEqual(res, {
      source: undefined,
      ok: false,
      problems: ["The answer had no ```lua code block."],
      rounds: DISSECTOR_LIMITS.rounds,
    });
  });
});
