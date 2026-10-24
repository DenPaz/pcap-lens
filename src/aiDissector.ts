/**
 * AI Lua dissector assistant: a description of a protocol's messages becomes
 * a Lua dissector built on PCAP Lens's template. Before tshark loads it (and
 * so runs its top-level code), the script is screened (`luaProblems`): it
 * must define the protocol it was asked for and may not use Lua's or
 * Wireshark's ways out of dissecting (os, io, require, load, Dir…). tshark's
 * Lua errors (`check_dissectors`) and the screen's findings go back to the
 * model for up to `DISSECTOR_LIMITS.rounds` answers. Only the description and
 * the template are sent, never capture data. No `vscode` import: unit-tested.
 */
import type { ChatTurn } from "./aiFilter";
import type { LuaDissectorSpec } from "./luaTemplate";

export const DISSECTOR_LIMITS = {
  /** Answers asked for in all (the first plus retries). */
  rounds: 3,
  /** A longer script is refused (and the model asked for a shorter one). */
  maxChars: 64_000,
  /** The description is cut there. */
  maxRequest: 4_000,
};

export interface DissectorRequest extends LuaDissectorSpec {
  /** What the messages hold, in the user's words. */
  layout: string;
}

/** The prompt: the template to start from, the request and the rules. */
export function buildDissectorPrompt(req: DissectorRequest, template: string): string {
  return [
    "You write Wireshark Lua dissectors (the Lua API of Wireshark 4.x: Proto, ProtoField, ProtoExpert,",
    "Tvb/TvbRange, TreeItem, DissectorTable). Write one complete dissector for the protocol described",
    "below, starting from the template (keep its header comment, protocol object and registration).",
    "Rules:",
    `- Keep Proto("${req.name}", …) and register it exactly as the template does: ${req.transport}.port ${req.port}.`,
    `- Every field is a ProtoField named "${req.name}.<field>" (lowercase, dots and underscores) with a`,
    "  fitting type (uint8/uint16/uint32/uint64, int*, bool, string, stringz, bytes, ipv4, ipv6, ether, …),",
    "  base and value strings for enumerations; list them all in <proto>.fields.",
    "- Check buffer:len() before every read and return 0 when the packet is too short to be this protocol.",
    "- Set pinfo.cols.protocol and a short pinfo.cols.info; return the number of bytes dissected.",
    "- Use only the dissection API: no os, io, require, load, loadstring, dofile, loadfile, package, debug,",
    "  Dir, _G or _ENV, and no global variables.",
    "- If the description leaves something open, choose the simplest reading and say so in a comment.",
    "Answer with the whole script in one ```lua code block and nothing else.",
    "",
    "Template:",
    "```lua",
    template.trimEnd(),
    "```",
    "",
    `Protocol: ${req.description.replace(/\s+/g, " ").trim()} (${req.name}, ${req.transport.toUpperCase()} port ${req.port})`,
    "Description of its messages:",
    req.layout.trim().slice(0, DISSECTOR_LIMITS.maxRequest),
  ].join("\n");
}

/** The Lua in an answer: its ```lua block, else its first fenced block, else the answer when it reads as Lua. */
export function extractLua(answer: string): string | undefined {
  const blocks = [...answer.matchAll(/```([\w+-]*)[^\n]*\n([\s\S]*?)```/g)];
  const lua = blocks.find((b) => b[1].toLowerCase() === "lua") ?? blocks[0];
  if (lua) {
    return lua[2].trimEnd() + "\n";
  }
  const text = answer.trim();
  return /^(--|local\s)/.test(text) ? text + "\n" : undefined;
}

/**
 * The code without comments and with string literals emptied (their quotes
 * kept), so the screen looks only at what runs.
 */
export function luaCode(source: string): string {
  let out = "";
  let i = 0;
  const longClose = (at: number): number | undefined => {
    const m = /^\[(=*)\[/.exec(source.slice(at, at + 64));
    if (!m) {
      return undefined;
    }
    const end = source.indexOf(`]${m[1]}]`, at + m[0].length);
    return end < 0 ? source.length : end + m[1].length + 2;
  };
  while (i < source.length) {
    const c = source[i];
    if (c === "-" && source[i + 1] === "-") {
      const end = longClose(i + 2);
      if (end !== undefined) {
        i = end;
      } else {
        const nl = source.indexOf("\n", i);
        i = nl < 0 ? source.length : nl;
      }
      out += " ";
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < source.length && source[j] !== c && source[j] !== "\n") {
        j += source[j] === "\\" ? 2 : 1;
      }
      out += `${c}${c}`;
      i = j + 1;
    } else if (c === "[" && longClose(i) !== undefined) {
      out += '""';
      i = longClose(i) ?? source.length;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/** Names a dissector has no business with: they reach files, programs or other code. */
const FORBIDDEN = [
  "os",
  "io",
  "require",
  "load",
  "loadstring",
  "loadfile",
  "dofile",
  "package",
  "debug",
  "Dir",
  "_G",
  "_ENV",
  "getfenv",
  "setfenv",
  "rawget",
  "rawset",
  "setmetatable",
  "getmetatable",
  "collectgarbage",
  "FileHandler",
  "register_filehandler",
  "Listener",
  "TextWindow",
  "browser_open_url",
  "browser_open_data_file",
  "run_user_scripts_when_superuser",
];

/** Why the script can't be loaded as is (empty: it may be). */
export function luaProblems(source: string, name: string): string[] {
  const problems: string[] = [];
  if (source.length > DISSECTOR_LIMITS.maxChars) {
    problems.push(`The script is longer than ${DISSECTOR_LIMITS.maxChars} characters.`);
  }
  const code = luaCode(source);
  const used = new Set<string>();
  // A name used as a value: not a field (x.os), not a method (x:load), not a table key (os = 1 inside {}).
  for (const m of code.matchAll(/(?<![\w.:])([A-Za-z_]\w*)/g)) {
    if (FORBIDDEN.includes(m[1])) {
      used.add(m[1]);
    }
  }
  if (/\bstring\s*\.\s*dump\b|:\s*dump\s*\(/.test(code)) {
    used.add("string.dump");
  }
  if (used.size) {
    problems.push(`It uses ${[...used].join(", ")}, which a dissector may not use.`);
  }
  if (!new RegExp(`\\bProto\\s*\\(\\s*["']${name}["']`).test(source)) {
    problems.push(`It doesn't define Proto("${name}", …).`);
  }
  if (!/DissectorTable\s*\.\s*get\s*\(/.test(code)) {
    problems.push("It doesn't register the protocol with DissectorTable.get(…):add(…).");
  }
  return problems;
}

/** The follow-up turn: what was wrong with the last script. */
export function buildDissectorRetryPrompt(problems: readonly string[]): string {
  return [
    "The script can't be used yet:",
    ...problems.map((p) => `- ${p.replace(/\s+/g, " ").trim().slice(0, 600)}`),
    "Reply with the whole corrected script in one ```lua code block.",
  ].join("\n");
}

export interface DissectorDeps {
  ask(turns: ChatTurn[]): Promise<string>;
  /** Load the script with tshark: its Lua errors (empty: it loads). */
  check(source: string): Promise<string[]>;
}

export interface DissectorResult {
  /** The last script (screened and loaded when `ok`). */
  source?: string;
  ok: boolean;
  /** The last script's problems or tshark's errors. */
  problems: string[];
  rounds: number;
}

/** Ask, screen, load with tshark; retry with what went wrong until it loads or the rounds run out. */
export async function generateDissector(
  deps: DissectorDeps,
  req: DissectorRequest,
  template: string,
  progress?: (round: number, problems: readonly string[]) => void,
): Promise<DissectorResult> {
  const turns: ChatTurn[] = [{ role: "user", content: buildDissectorPrompt(req, template) }];
  let result: DissectorResult = { ok: false, problems: [], rounds: 0 };
  for (let round = 1; round <= DISSECTOR_LIMITS.rounds; round++) {
    progress?.(round, result.problems);
    const answer = await deps.ask(turns);
    const source = extractLua(answer);
    let problems = source
      ? luaProblems(source, req.name)
      : ["The answer had no ```lua code block."];
    // Only a screened script is ever loaded: loading runs its top-level code.
    if (source && !problems.length) {
      problems = await deps.check(source);
    }
    result = { source: source ?? result.source, ok: !problems.length, problems, rounds: round };
    if (result.ok) {
      break;
    }
    turns.push(
      { role: "assistant", content: answer },
      { role: "user", content: buildDissectorRetryPrompt(problems) },
    );
  }
  return result;
}
