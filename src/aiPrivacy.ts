/**
 * Stand-ins for addresses and host names in what the AI features send
 * (`pcapViewer.ai.pseudonymizeAddresses`, on by default). Before text goes to
 * the language model, IPv4, IPv6 and MAC addresses and the host names that
 * name resolution showed become tokens (IP_PRIVATE_1, IP_PUBLIC_2,
 * IP6_LOCAL_1, IP6_PUBLIC_1, MAC_3, HOST_4); the answer, the filters in it
 * and the tools' inputs get the real values back. One masker per capture
 * (backend), so a token means the same address in every request about it.
 *
 * What is kept as is reveals nothing about a machine: unspecified, loopback,
 * multicast and broadcast addresses, and MAC group addresses. Private and
 * public addresses get different tokens: the difference matters to an
 * analysis and says little. No `vscode` import: unit-tested.
 */
import { isIPv6 } from "node:net";
import type { LoopMessage, LoopModel, LoopPart, ToolSpec } from "./aiTools";

const KINDS = ["IP_PRIVATE", "IP_PUBLIC", "IP6_LOCAL", "IP6_PUBLIC", "MAC", "HOST"] as const;
export type StandInKind = (typeof KINDS)[number];

/** Told to the model whenever stand-ins are used. */
export const STAND_IN_NOTE =
  "Addresses and host names in this conversation are replaced by stand-ins such as IP_PRIVATE_1, " +
  "IP_PUBLIC_2, IP6_LOCAL_1, IP6_PUBLIC_1, MAC_3 and HOST_4 (each always stands for the same address; " +
  "IP_PRIVATE means a private or link-local address). Use them exactly as written, also inside display " +
  "filters (e.g. ip.addr == IP_PRIVATE_1); they are turned back into the real values for the user.";

const TOKEN_RE = new RegExp(`\\b(${KINDS.join("|")})_(\\d+)\\b`, "g");
// (A run that may still grow into a token at the end of a streamed chunk.)
const TAIL_RE = /[A-Z0-9_]+$/;
const MAX_TOKEN = 20;

const IPV4_RE = /(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w]|\.\d)/g;
// Candidates only: isIPv6 decides (times like 12:34:56 aren't addresses).
const IPV6_RE = /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])/g;
const MAC_RE = /(?<![\w:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])/g;
// tshark's resolved form: the vendor and the last three bytes ("Apple_12:34:56").
const VENDOR_MAC_RE = /(?<![\w:-])[A-Za-z][\w-]*_[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}(?![\w:-])/g;

function ipv4Kind(octets: number[]): StandInKind | undefined {
  const [a, b] = octets;
  if (octets.some((o) => o > 255)) {
    return undefined; // not an address
  }
  if (a === 0 || a === 127 || a >= 224) {
    return undefined; // unspecified, loopback, multicast, reserved, broadcast: kept
  }
  const isPrivate =
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254);
  return isPrivate ? "IP_PRIVATE" : "IP_PUBLIC";
}

function ipv6Kind(text: string): StandInKind | undefined {
  const lower = text.toLowerCase();
  if (!isIPv6(lower) || lower === "::" || lower === "::1" || lower.startsWith("ff")) {
    return undefined;
  }
  const first = lower.split(":")[0].padStart(4, "0");
  return /^fe[89ab]/.test(first) || /^f[cd]/.test(first) ? "IP6_LOCAL" : "IP6_PUBLIC";
}

function macKind(text: string): StandInKind | undefined {
  // Group addresses (broadcast, multicast) name no machine; all-zero neither.
  const first = parseInt(text.slice(0, 2), 16);
  return first & 1 || /^0{2}([:-]0{2}){5}$/.test(text) ? undefined : "MAC";
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export interface Restorer {
  /** The restored text that is safe to show now (a possible token's start is held back). */
  push(chunk: string): string;
  /** Whatever was held back. */
  end(): string;
}

export class AddressMasker {
  /** Real value (normalized) → token. */
  private readonly tokens = new Map<string, string>();
  /** Token → real value as first seen. */
  private readonly reals = new Map<string, string>();
  private readonly counts = new Map<StandInKind, number>();
  /** Host names learned from the capture → the key of what they stand for. */
  private readonly names = new Map<string, string>();
  private namesRe: RegExp | undefined;

  constructor(readonly enabled = true) {}

  private token(kind: StandInKind, key: string, real: string): string {
    let token = this.tokens.get(key);
    if (!token) {
      const n = (this.counts.get(kind) ?? 0) + 1;
      this.counts.set(kind, n);
      token = `${kind}_${n}`;
      this.tokens.set(key, token);
      this.reals.set(token, real);
    }
    return token;
  }

  /**
   * Host names the capture showed (name resolution), each with the address
   * it stands for when known: the name then gets that address's token, else
   * a HOST token. Short names and addresses are ignored.
   */
  learnNames(pairs: Iterable<{ name: string; address?: string }>): void {
    if (!this.enabled) {
      return;
    }
    let added = false;
    for (const { name, address } of pairs) {
      const n = name.trim();
      if (n.length < 3 || this.names.has(n) || /\s/.test(n) || this.maskAddresses(n) !== n) {
        continue;
      }
      const masked = address ? this.maskAddresses(address.trim()) : "";
      this.names.set(n, masked && masked !== address?.trim() ? masked : this.token("HOST", n, n));
      added = true;
    }
    if (added) {
      const all = [...this.names.keys()].sort((a, b) => b.length - a.length).map(escapeRe);
      this.namesRe = new RegExp(`(?<![\\w.-])(?:${all.join("|")})(?![\\w-]|\\.\\w)`, "g");
    }
  }

  private maskAddresses(text: string): string {
    return text
      .replace(MAC_RE, (m) => {
        const kind = macKind(m);
        return kind ? this.token(kind, m.toLowerCase().replace(/-/g, ":"), m) : m;
      })
      .replace(VENDOR_MAC_RE, (m) => this.token("MAC", m.toLowerCase(), m))
      .replace(IPV6_RE, (m) => {
        const kind = ipv6Kind(m);
        return kind ? this.token(kind, m.toLowerCase(), m) : m;
      })
      .replace(IPV4_RE, (m, ...groups: string[]) => {
        const kind = ipv4Kind(groups.slice(0, 4).map(Number));
        return kind ? this.token(kind, m, m) : m;
      });
  }

  /** The text with stand-ins for its addresses and learned host names. */
  mask(text: string): string {
    if (!this.enabled || !text) {
      return text;
    }
    const named = this.namesRe ? text.replace(this.namesRe, (m) => this.names.get(m) ?? m) : text;
    return this.maskAddresses(named);
  }

  /** The text with the real values back (unknown tokens stay). */
  restore(text: string): string {
    if (!this.enabled || !text) {
      return text;
    }
    return text.replace(TOKEN_RE, (m) => this.reals.get(m) ?? m);
  }

  /** Strings inside a value (a tool call's input) restored. */
  restoreDeep(value: unknown): unknown {
    return this.mapStrings(value, (s) => this.restore(s));
  }

  /** Strings inside a value masked. */
  maskDeep(value: unknown): unknown {
    return this.mapStrings(value, (s) => this.mask(s));
  }

  private mapStrings(value: unknown, f: (s: string) => string): unknown {
    if (!this.enabled) {
      return value;
    }
    if (typeof value === "string") {
      return f(value);
    }
    if (Array.isArray(value)) {
      return value.map((v) => this.mapStrings(v, f));
    }
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, this.mapStrings(v, f)]));
    }
    return value;
  }

  /** How many different addresses and names have stand-ins. */
  get size(): number {
    return this.reals.size;
  }

  /** Restores a streamed answer chunk by chunk (a token can be split between chunks). */
  restorer(): Restorer {
    let held = "";
    return {
      push: (chunk) => {
        const text = held + chunk;
        const tail = TAIL_RE.exec(text)?.[0] ?? "";
        const keep =
          this.enabled && tail.length <= MAX_TOKEN && couldBeToken(tail) ? tail.length : 0;
        held = text.slice(text.length - keep);
        return this.restore(text.slice(0, text.length - keep));
      },
      end: () => {
        const rest = held;
        held = "";
        return this.restore(rest);
      },
    };
  }
}

/** Whether `run` is the start of a token (or a whole one, which may still grow digits). */
function couldBeToken(run: string): boolean {
  if (!run) {
    return false;
  }
  return KINDS.some((kind) => {
    const prefix = `${kind}_`;
    return (
      prefix.startsWith(run) || (run.startsWith(prefix) && /^\d*$/.test(run.slice(prefix.length)))
    );
  });
}

/** A text with STAND_IN_NOTE first when stand-ins are on. */
export function withStandInNote(masker: AddressMasker, text: string): string {
  return masker.enabled ? `${STAND_IN_NOTE}\n\n${text}` : text;
}

/**
 * A tool-calling model that sees stand-ins: what is sent (the question, tool
 * results, earlier tool calls) is masked, what comes back (the answer, the
 * tools' inputs) is restored, so tools run with real values.
 */
export function maskedLoopModel(inner: LoopModel, masker: AddressMasker): LoopModel {
  if (!masker.enabled) {
    return inner;
  }
  const maskPart = (p: LoopPart): LoopPart =>
    p.type === "call"
      ? { ...p, input: masker.maskDeep(p.input) }
      : { ...p, text: masker.mask(p.text) };
  return {
    async *send(messages: readonly LoopMessage[], tools: readonly ToolSpec[]) {
      const masked = messages.map((m, i) => ({
        role: m.role,
        parts: m.parts
          .map(maskPart)
          .map((p) =>
            i === 0 && p.type === "text" ? { ...p, text: withStandInNote(masker, p.text) } : p,
          ),
      }));
      const restorer = masker.restorer();
      for await (const part of inner.send(masked, tools)) {
        if (part.type === "text") {
          const text = restorer.push(part.text);
          if (text) {
            yield { type: "text", text } satisfies LoopPart;
          }
        } else if (part.type === "call") {
          const rest = restorer.end();
          if (rest) {
            yield { type: "text", text: rest } satisfies LoopPart;
          }
          yield { ...part, input: masker.restoreDeep(part.input) };
        } else {
          yield part;
        }
      }
      const rest = restorer.end();
      if (rest) {
        yield { type: "text", text: rest } satisfies LoopPart;
      }
    },
  };
}

/** A detail tree node (only what the name harvest reads). */
interface NamedNode {
  name?: string;
  show?: string;
  children?: NamedNode[];
}

/**
 * Host names a dissection tree shows from name resolution (`ip.src_host`,
 * `ipv6.dst_host`, `ip.host`…), each with its address field's value from the
 * same protocol (`ip.src`, `ip.addr`…).
 */
export function namesInTree(tree: readonly NamedNode[]): { name: string; address?: string }[] {
  const out: { name: string; address?: string }[] = [];
  const walk = (nodes: readonly NamedNode[]) => {
    for (const node of nodes) {
      const m = /^(.+)\.(src_host|dst_host|host)$/.exec(node.name ?? "");
      if (m && node.show) {
        const field = `${m[1]}.${m[2] === "host" ? "addr" : m[2].replace("_host", "")}`;
        out.push({ name: node.show, address: nodes.find((n) => n.name === field)?.show });
      }
      walk(node.children ?? []);
    }
  };
  walk(tree);
  return out;
}

/** Host names packet-list rows show (Source/Destination with `addresses` behind them). */
export function namesInRows(
  rows: readonly { cells: string[]; addresses?: string[] }[],
): { name: string; address: string }[] {
  const out: { name: string; address: string }[] = [];
  for (const row of rows) {
    row.addresses?.forEach((address, i) => {
      const shown = row.cells[2 + i];
      if (address && shown && shown !== address) {
        out.push({ name: shown, address });
      }
    });
  }
  return out;
}
