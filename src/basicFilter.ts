/**
 * Display filters in the basic view (src/basicCapture.ts): the common part of
 * Wireshark's filter language, evaluated over the fields the basic dissector
 * reads. Pure (no `vscode` import).
 *
 * Supported: protocol and field names alone (present), the comparisons
 * `== != === !== > < >= <=` and their word forms (`eq`, `ne`, `all_eq`,
 * `any_ne`, `gt`…), `contains`, `matches` (JavaScript regular expressions,
 * `(?i)` for any case), `in {…}` with ranges (`80..90`), `and`/`&&`,
 * `or`/`||`, `xor`/`^^`, `not`/`!` and parentheses; IPv4 and IPv6 networks
 * (`ip.addr == 10.0.0.0/8`), MAC addresses, numbers in decimal or hex,
 * booleans as 1/0 or True/False, strings in quotes and byte strings
 * (`frame contains 47:45:54`). As in Wireshark, `and` binds tighter than `or`,
 * `!=` means "no value equals" and a comparison with an absent field is false.
 * Slices, functions, arithmetic and field references need tshark: they are
 * refused with an error that says so, as is a name the basic view doesn't read.
 */

export type FieldType =
  | "FT_PROTOCOL"
  | "FT_NONE"
  | "FT_BOOLEAN"
  | "FT_UINT8"
  | "FT_UINT16"
  | "FT_UINT24"
  | "FT_UINT32"
  | "FT_FRAMENUM"
  | "FT_RELATIVE_TIME"
  | "FT_IPv4"
  | "FT_IPv6"
  | "FT_ETHER"
  | "FT_STRING"
  | "FT_BYTES";

export interface BasicField {
  name: string;
  type: FieldType;
  desc: string;
}

/** A field's value in one packet: a number, a text, or bytes (protocols, byte fields). */
export type FieldValue = number | string | Buffer;

/** The protocols the basic dissector decodes, as tshark names them. */
export const BASIC_PROTOCOLS: { name: string; desc: string }[] = [
  { name: "arp", desc: "Address Resolution Protocol" },
  { name: "data", desc: "Data" },
  { name: "dns", desc: "Domain Name System" },
  { name: "eth", desc: "Ethernet" },
  { name: "frame", desc: "Frame" },
  { name: "http", desc: "Hypertext Transfer Protocol" },
  { name: "icmp", desc: "Internet Control Message Protocol" },
  { name: "icmpv6", desc: "Internet Control Message Protocol v6" },
  { name: "ip", desc: "Internet Protocol Version 4" },
  { name: "ipv6", desc: "Internet Protocol Version 6" },
  { name: "llc", desc: "Logical-Link Control" },
  { name: "mdns", desc: "Multicast Domain Name System" },
  { name: "null", desc: "Null/Loopback" },
  { name: "radiotap", desc: "IEEE 802.11 Radiotap Capture header" },
  { name: "sll", desc: "Linux cooked-mode capture" },
  { name: "tcp", desc: "Transmission Control Protocol" },
  { name: "tls", desc: "Transport Layer Security" },
  { name: "udp", desc: "User Datagram Protocol" },
  { name: "vlan", desc: "802.1Q Virtual LAN" },
  { name: "wlan", desc: "IEEE 802.11 wireless LAN" },
];

const f = (name: string, type: FieldType, desc: string): BasicField => ({ name, type, desc });

/** The fields the basic dissector reads (tshark's names, types and descriptions). */
export const BASIC_FIELDS: BasicField[] = [
  f("_ws.col.def_dst", "FT_STRING", "Destination"),
  f("_ws.col.def_src", "FT_STRING", "Source"),
  f("_ws.col.info", "FT_STRING", "Information"),
  f("_ws.col.protocol", "FT_STRING", "Protocol"),
  f("_ws.malformed", "FT_PROTOCOL", "Malformed Packet"),
  f("arp.dst.hw_mac", "FT_ETHER", "Target MAC address"),
  f("arp.dst.proto_ipv4", "FT_IPv4", "Target IP address"),
  f("arp.opcode", "FT_UINT16", "Opcode"),
  f("arp.src.hw_mac", "FT_ETHER", "Sender MAC address"),
  f("arp.src.proto_ipv4", "FT_IPv4", "Sender IP address"),
  f("data.data", "FT_BYTES", "Data"),
  f("data.len", "FT_UINT32", "Length"),
  f("dns.a", "FT_IPv4", "Address"),
  f("dns.aaaa", "FT_IPv6", "AAAA Address"),
  f("dns.cname", "FT_STRING", "CNAME"),
  f("dns.count.answers", "FT_UINT16", "Answer RRs"),
  f("dns.count.queries", "FT_UINT16", "Questions"),
  f("dns.flags", "FT_UINT16", "Flags"),
  f("dns.flags.rcode", "FT_UINT16", "Reply code"),
  f("dns.flags.response", "FT_BOOLEAN", "Response"),
  f("dns.id", "FT_UINT16", "Transaction ID"),
  f("dns.qry.name", "FT_STRING", "Name"),
  f("dns.qry.type", "FT_UINT16", "Type"),
  f("dns.resp.name", "FT_STRING", "Name"),
  f("dns.resp.type", "FT_UINT16", "Type"),
  f("eth.addr", "FT_ETHER", "Address"),
  f("eth.dst", "FT_ETHER", "Destination"),
  f("eth.src", "FT_ETHER", "Source"),
  f("eth.type", "FT_UINT16", "Type"),
  f("frame.cap_len", "FT_UINT32", "Frame length stored into the capture file"),
  f("frame.len", "FT_UINT32", "Frame length on the wire"),
  f("frame.number", "FT_UINT32", "Frame Number"),
  f("frame.time_relative", "FT_RELATIVE_TIME", "Time since reference or first frame"),
  f("http.request", "FT_NONE", "Request"),
  f("http.request.method", "FT_STRING", "Request Method"),
  f("http.request.uri", "FT_STRING", "Request URI"),
  f("http.request.version", "FT_STRING", "Request Version"),
  f("http.response", "FT_NONE", "Response"),
  f("http.response.code", "FT_UINT24", "Status Code"),
  f("http.response.phrase", "FT_STRING", "Response Phrase"),
  f("http.response.version", "FT_STRING", "Response Version"),
  f("icmp.checksum", "FT_UINT16", "Checksum"),
  f("icmp.code", "FT_UINT8", "Code"),
  f("icmp.ident", "FT_UINT16", "Identifier (BE)"),
  f("icmp.seq", "FT_UINT16", "Sequence Number (BE)"),
  f("icmp.type", "FT_UINT8", "Type"),
  f("icmpv6.code", "FT_UINT8", "Code"),
  f("icmpv6.nd.ns.target_address", "FT_IPv6", "Target Address"),
  f("icmpv6.type", "FT_UINT8", "Type"),
  f("ip.addr", "FT_IPv4", "Source or Destination Address"),
  f("ip.checksum", "FT_UINT16", "Header Checksum"),
  f("ip.dst", "FT_IPv4", "Destination Address"),
  f("ip.flags", "FT_UINT8", "Flags"),
  f("ip.flags.df", "FT_BOOLEAN", "Don't fragment"),
  f("ip.flags.mf", "FT_BOOLEAN", "More fragments"),
  f("ip.frag_offset", "FT_UINT16", "Fragment Offset"),
  f("ip.hdr_len", "FT_UINT8", "Header Length"),
  f("ip.id", "FT_UINT16", "Identification"),
  f("ip.len", "FT_UINT16", "Total Length"),
  f("ip.proto", "FT_UINT8", "Protocol"),
  f("ip.src", "FT_IPv4", "Source Address"),
  f("ip.ttl", "FT_UINT8", "Time to Live"),
  f("ip.version", "FT_UINT8", "Version"),
  f("ipv6.addr", "FT_IPv6", "Source or Destination Address"),
  f("ipv6.dst", "FT_IPv6", "Destination Address"),
  f("ipv6.hlim", "FT_UINT8", "Hop Limit"),
  f("ipv6.nxt", "FT_UINT8", "Next Header"),
  f("ipv6.plen", "FT_UINT16", "Payload Length"),
  f("ipv6.src", "FT_IPv6", "Source Address"),
  f("ipv6.version", "FT_UINT8", "Version"),
  f("llc.type", "FT_UINT16", "Type"),
  f("null.family", "FT_UINT32", "Family"),
  f("radiotap.length", "FT_UINT16", "Header length"),
  f("sll.etype", "FT_UINT16", "Protocol"),
  f("sll.ifindex", "FT_UINT32", "Interface index"),
  f("sll.pkttype", "FT_UINT16", "Packet type"),
  f("sll.src.eth", "FT_ETHER", "Source"),
  f("tcp.ack_raw", "FT_UINT32", "Acknowledgment number (raw)"),
  f("tcp.checksum", "FT_UINT16", "Checksum"),
  f("tcp.dstport", "FT_UINT16", "Destination Port"),
  f("tcp.flags", "FT_UINT16", "Flags"),
  f("tcp.flags.ack", "FT_BOOLEAN", "Acknowledgment"),
  f("tcp.flags.fin", "FT_BOOLEAN", "Fin"),
  f("tcp.flags.push", "FT_BOOLEAN", "Push"),
  f("tcp.flags.reset", "FT_BOOLEAN", "Reset"),
  f("tcp.flags.syn", "FT_BOOLEAN", "Syn"),
  f("tcp.flags.urg", "FT_BOOLEAN", "Urgent"),
  f("tcp.hdr_len", "FT_UINT8", "Header Length"),
  f("tcp.len", "FT_UINT32", "TCP Segment Len"),
  f("tcp.options", "FT_BYTES", "TCP Options"),
  f("tcp.port", "FT_UINT16", "Source or Destination Port"),
  f("tcp.seq_raw", "FT_UINT32", "Sequence Number (raw)"),
  f("tcp.srcport", "FT_UINT16", "Source Port"),
  f("tcp.urgent_pointer", "FT_UINT16", "Urgent Pointer"),
  f("tcp.window_size_value", "FT_UINT16", "Window"),
  f("tls.handshake.type", "FT_UINT8", "Handshake Type"),
  f("tls.record", "FT_NONE", "TLS Record Layer"),
  f("tls.record.content_type", "FT_UINT8", "Content Type"),
  f("tls.record.length", "FT_UINT16", "Length"),
  f("tls.record.version", "FT_UINT16", "Version"),
  f("udp.checksum", "FT_UINT16", "Checksum"),
  f("udp.dstport", "FT_UINT16", "Destination Port"),
  f("udp.length", "FT_UINT16", "Length"),
  f("udp.port", "FT_UINT16", "Source or Destination Port"),
  f("udp.srcport", "FT_UINT16", "Source Port"),
  f("vlan.etype", "FT_UINT16", "Type"),
  f("vlan.id", "FT_UINT16", "ID"),
  f("wlan.addr", "FT_ETHER", "Hardware address"),
  f("wlan.fc", "FT_UINT16", "Frame Control Field"),
  f("wlan.ra", "FT_ETHER", "Receiver address"),
  f("wlan.ta", "FT_ETHER", "Transmitter address"),
];

const FIELDS = new Map<string, FieldType>([
  ...BASIC_PROTOCOLS.map((p): [string, FieldType] => [p.name, "FT_PROTOCOL"]),
  ...BASIC_FIELDS.map((x): [string, FieldType] => [x.name, x.type]),
]);

/** The type of a field or protocol the basic view reads, else undefined. */
export function basicFieldType(name: string): FieldType | undefined {
  return FIELDS.get(name);
}

const MAX_UINT: Partial<Record<FieldType, number>> = {
  FT_UINT8: 0xff,
  FT_UINT16: 0xffff,
  FT_UINT24: 0xffffff,
  FT_UINT32: 0xffffffff,
  FT_FRAMENUM: 0xffffffff,
};

/** A filter the basic view can't read, with the part of it at fault ([start, end), UTF-16). */
export class BasicFilterError extends Error {
  constructor(
    message: string,
    readonly span: [number, number] | null,
  ) {
    super(message);
  }
}

const NEEDS_TSHARK = "the basic view reads only the common part of the filter language";

// -- tokens ------------------------------------------------------------------------------

type TokenKind = "word" | "string" | "op" | "punct" | "end";
interface Token {
  kind: TokenKind;
  text: string;
  /** A string's value (escapes resolved); a word's text. */
  value: string;
  start: number;
  end: number;
}

const OPERATORS = ["===", "!==", "==", "!=", ">=", "<=", "&&", "||", "^^", ">", "<", "!", "~"];
const WORD = /[A-Za-z0-9_.:\-/]/;

function tokenize(expr: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < expr.length) {
    const c = expr[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    const start = i;
    if (c === '"' || ((c === "r" || c === "R") && expr[i + 1] === '"')) {
      const raw = c !== '"';
      i += raw ? 2 : 1;
      let value = "";
      for (;;) {
        if (i >= expr.length) {
          throw new BasicFilterError("The string has no closing quote.", [start, expr.length]);
        }
        const ch = expr[i];
        if (ch === '"') {
          i++;
          break;
        }
        if (ch === "\\" && !raw) {
          const next = expr[i + 1] ?? "";
          const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0" };
          if (next === "x" && /^[0-9a-fA-F]{2}$/.test(expr.slice(i + 2, i + 4))) {
            value += String.fromCharCode(parseInt(expr.slice(i + 2, i + 4), 16));
            i += 4;
          } else if (next in simple) {
            value += simple[next];
            i += 2;
          } else {
            value += next;
            i += 2;
          }
          continue;
        }
        if (ch === "\\" && raw && expr[i + 1] === '"') {
          value += '\\"';
          i += 2;
          continue;
        }
        value += ch;
        i++;
      }
      tokens.push({ kind: "string", text: expr.slice(start, i), value, start, end: i });
      continue;
    }
    if ("(){},".includes(c)) {
      tokens.push({ kind: "punct", text: c, value: c, start, end: i + 1 });
      i++;
      continue;
    }
    if (c === "[") {
      throw new BasicFilterError(`Slices ("[…]") need tshark: ${NEEDS_TSHARK}.`, [
        start,
        start + 1,
      ]);
    }
    if (c === "$") {
      throw new BasicFilterError(
        `Field references and macros ("$…") need tshark: ${NEEDS_TSHARK}.`,
        [start, start + 1],
      );
    }
    const op = OPERATORS.find((o) => expr.startsWith(o, i));
    if (op) {
      tokens.push({ kind: "op", text: op, value: op, start, end: i + op.length });
      i += op.length;
      continue;
    }
    if (WORD.test(c)) {
      while (i < expr.length && WORD.test(expr[i])) {
        i++;
      }
      const text = expr.slice(start, i);
      tokens.push({ kind: "word", text, value: text, start, end: i });
      continue;
    }
    if ("+*%&|^".includes(c)) {
      throw new BasicFilterError(`Arithmetic needs tshark: ${NEEDS_TSHARK}.`, [start, start + 1]);
    }
    throw new BasicFilterError(`"${c}" was unexpected in this context.`, [start, start + 1]);
  }
  tokens.push({ kind: "end", text: "", value: "", start: expr.length, end: expr.length });
  return tokens;
}

// -- syntax tree -------------------------------------------------------------------------

type Relation = "any_eq" | "all_ne" | "all_eq" | "any_ne" | "gt" | "lt" | "ge" | "le";

/** A literal converted for one field type. */
type Literal =
  | { kind: "number"; value: number }
  | { kind: "net4"; addr: number; mask: number }
  | { kind: "net6"; addr: bigint; bits: number }
  | { kind: "ether"; value: string }
  | { kind: "string"; value: string }
  | { kind: "bytes"; value: Buffer };

export type Node =
  | { op: "and" | "or" | "xor"; left: Node; right: Node }
  | { op: "not"; arg: Node }
  | { op: "exists"; field: string }
  | { op: "compare"; field: string; type: FieldType; rel: Relation; value: Literal }
  | { op: "contains"; field: string; type: FieldType; value: Buffer | string }
  | { op: "matches"; field: string; type: FieldType; regex: RegExp }
  | { op: "in"; field: string; type: FieldType; items: { lo: Literal; hi?: Literal }[] };

const RELATIONS: Record<string, Relation> = {
  "==": "any_eq",
  eq: "any_eq",
  any_eq: "any_eq",
  "!=": "all_ne",
  ne: "all_ne",
  all_ne: "all_ne",
  "===": "all_eq",
  all_eq: "all_eq",
  "!==": "any_ne",
  any_ne: "any_ne",
  ">": "gt",
  gt: "gt",
  "<": "lt",
  lt: "lt",
  ">=": "ge",
  ge: "ge",
  "<=": "le",
  le: "le",
};
const KEYWORDS = new Set([
  "and",
  "or",
  "xor",
  "not",
  "in",
  "contains",
  "matches",
  ...Object.keys(RELATIONS),
]);

class Parser {
  private i = 0;
  constructor(
    private readonly expr: string,
    private readonly tokens: Token[],
  ) {}

  private get tok(): Token {
    return this.tokens[this.i];
  }
  private is(...words: string[]): boolean {
    const t = this.tok;
    return (t.kind === "op" || t.kind === "word" || t.kind === "punct") && words.includes(t.text);
  }
  private fail(message: string, t = this.tok): never {
    if (t.kind === "end") {
      throw new BasicFilterError("Unexpected end of filter expression.", [
        this.expr.trimEnd().length,
        this.expr.trimEnd().length,
      ]);
    }
    throw new BasicFilterError(message, [t.start, t.end]);
  }

  parse(): Node {
    const node = this.or();
    if (this.tok.kind !== "end") {
      this.fail(`"${this.tok.text}" was unexpected in this context.`);
    }
    return node;
  }

  private or(): Node {
    let left = this.xor();
    while (this.is("||", "or")) {
      this.i++;
      left = { op: "or", left, right: this.xor() };
    }
    return left;
  }
  private xor(): Node {
    let left = this.and();
    while (this.is("^^", "xor")) {
      this.i++;
      left = { op: "xor", left, right: this.and() };
    }
    return left;
  }
  private and(): Node {
    let left = this.not();
    while (this.is("&&", "and")) {
      this.i++;
      left = { op: "and", left, right: this.not() };
    }
    return left;
  }
  private not(): Node {
    if (this.is("!", "not")) {
      this.i++;
      return { op: "not", arg: this.not() };
    }
    return this.primary();
  }

  private primary(): Node {
    const t = this.tok;
    if (t.kind === "punct" && t.text === "(") {
      this.i++;
      const inner = this.or();
      if (!this.is(")")) {
        this.fail(`"${this.tok.text}" was unexpected in this context: a ")" is missing.`);
      }
      this.i++;
      return inner;
    }
    if (t.kind !== "word" || KEYWORDS.has(t.text)) {
      this.fail(`"${t.text}" was unexpected in this context.`);
    }
    const next = this.tokens[this.i + 1];
    if (next.kind === "punct" && next.text === "(" && next.start === t.end) {
      throw new BasicFilterError(`Functions such as ${t.text}() need tshark: ${NEEDS_TSHARK}.`, [
        t.start,
        next.end,
      ]);
    }
    const type = FIELDS.get(t.text);
    if (type === undefined) {
      throw new BasicFilterError(
        /^[A-Za-z_][\w-]*(\.[\w-]+)*$/.test(t.text)
          ? `"${t.text}" isn't a field the basic view reads (Ctrl+Space lists those it does); every field needs tshark.`
          : `"${t.text}" is neither a field nor a protocol name.`,
        [t.start, t.end],
      );
    }
    this.i++;
    const field = t.text;
    const rel = this.tok;
    if ((rel.kind === "op" || rel.kind === "word") && rel.text in RELATIONS) {
      this.i++;
      return {
        op: "compare",
        field,
        type,
        rel: RELATIONS[rel.text],
        value: this.literal(field, type, this.value(), RELATIONS[rel.text]),
      };
    }
    if (this.is("contains")) {
      this.i++;
      const v = this.value();
      return { op: "contains", field, type, value: this.containsValue(field, type, v) };
    }
    if (this.is("matches", "~")) {
      this.i++;
      const v = this.value();
      if (v.kind !== "string") {
        this.fail('"matches" takes a regular expression in quotes.', v);
      }
      this.textual(field, type, v);
      return { op: "matches", field, type, regex: regex(v) };
    }
    if (this.is("in") || (this.is("not") && this.tokens[this.i + 1]?.text === "in")) {
      const negate = this.tok.text === "not";
      this.i += negate ? 2 : 1;
      const node: Node = { op: "in", field, type, items: this.set(field, type) };
      return negate ? { op: "not", arg: node } : node;
    }
    return { op: "exists", field };
  }

  private value(): Token {
    const t = this.tok;
    if (t.kind === "string" || (t.kind === "word" && !KEYWORDS.has(t.text))) {
      this.i++;
      return t;
    }
    return this.fail(`"${t.text}" was unexpected in this context.`);
  }

  private set(field: string, type: FieldType): { lo: Literal; hi?: Literal }[] {
    if (!this.is("{")) {
      this.fail('"in" takes a set in braces, such as {80, 443}.');
    }
    this.i++;
    const items: { lo: Literal; hi?: Literal }[] = [];
    while (!this.is("}")) {
      if (items.length && this.is(",")) {
        this.i++;
      }
      const v = this.value();
      const range = v.kind === "word" ? v.text.split("..") : [];
      if (range.length === 2 && range[0] && range[1]) {
        const at = v.start + range[0].length + 2;
        items.push({
          lo: this.literal(
            field,
            type,
            { ...v, text: range[0], value: range[0], end: v.start + range[0].length },
            "ge",
          ),
          hi: this.literal(field, type, { ...v, text: range[1], value: range[1], start: at }, "le"),
        });
      } else {
        items.push({ lo: this.literal(field, type, v, "any_eq") });
      }
      if (this.tok.kind === "end") {
        this.fail("");
      }
    }
    this.i++;
    if (!items.length) {
      this.fail("The set is empty.", this.tokens[this.i - 1]);
    }
    return items;
  }

  private textual(field: string, type: FieldType, v: Token): void {
    if (!["FT_STRING", "FT_BYTES", "FT_PROTOCOL"].includes(type)) {
      throw new BasicFilterError(`"${field}" is a ${typeName(type)}: it can't hold text.`, [
        v.start,
        v.end,
      ]);
    }
  }

  private containsValue(field: string, type: FieldType, v: Token): Buffer | string {
    this.textual(field, type, v);
    if (type === "FT_STRING") {
      return v.value;
    }
    return v.kind === "string" ? Buffer.from(v.value, "latin1") : this.bytes(v);
  }

  private bytes(v: Token): Buffer {
    const hex = v.text.split(/[:.-]/);
    if (hex.every((h) => /^[0-9a-fA-F]{2}$/.test(h))) {
      return Buffer.from(hex.join(""), "hex");
    }
    if (/^[0-9a-fA-F]{2}$/.test(v.text)) {
      return Buffer.from(v.text, "hex");
    }
    return this.fail(
      `"${v.text}" isn't a byte string: write bytes as aa:bb:cc, or text in quotes.`,
      v,
    );
  }

  /** Convert `v` for a comparison with `field`, as tshark would read it. */
  private literal(field: string, type: FieldType, v: Token, rel: Relation): Literal {
    const bad = (what: string): never => this.fail(`"${v.value}" isn't ${what}.`, v);
    switch (type) {
      case "FT_PROTOCOL":
      case "FT_NONE":
        if (type === "FT_NONE") {
          throw new BasicFilterError(
            `"${field}" is a label: it can only be tested for being there ("${field}" alone).`,
            [v.start, v.end],
          );
        }
        if (rel !== "any_eq" && rel !== "all_ne" && rel !== "all_eq" && rel !== "any_ne") {
          bad("something a protocol can be ordered by");
        }
        return {
          kind: "bytes",
          value: v.kind === "string" ? Buffer.from(v.value, "latin1") : this.bytes(v),
        };
      case "FT_BYTES":
        return {
          kind: "bytes",
          value: v.kind === "string" ? Buffer.from(v.value, "latin1") : this.bytes(v),
        };
      case "FT_STRING":
        return { kind: "string", value: v.value };
      case "FT_BOOLEAN": {
        const t = v.value.toLowerCase();
        if (t === "true" || t === "1") {
          return { kind: "number", value: 1 };
        }
        if (t === "false") {
          return { kind: "number", value: 0 };
        }
        // (As tshark: any other number is true.)
        const n = parseUint(v.value);
        return n !== null
          ? { kind: "number", value: n ? 1 : 0 }
          : bad("a boolean (1, 0, True or False)");
      }
      case "FT_RELATIVE_TIME": {
        const n = Number(v.value);
        return Number.isFinite(n) && /^-?[\d.]+$/.test(v.value)
          ? { kind: "number", value: n }
          : bad("a time in seconds");
      }
      case "FT_IPv4": {
        const net = parseNet4(v.value);
        return net ?? bad("an IPv4 address or network");
      }
      case "FT_IPv6": {
        const net = parseNet6(v.value);
        return net ?? bad("an IPv6 address or network");
      }
      case "FT_ETHER": {
        const m = normalizeMac(v.value);
        return m ? { kind: "ether", value: m } : bad("a MAC address");
      }
      default: {
        const n = parseUint(v.value);
        if (n === null) {
          return bad("a number");
        }
        const max = MAX_UINT[type] ?? Number.MAX_SAFE_INTEGER;
        if (n > max) {
          throw new BasicFilterError(`"${v.value}" too big for this field, maximum ${max}.`, [
            v.start,
            v.end,
          ]);
        }
        return { kind: "number", value: n };
      }
    }
  }
}

function typeName(type: FieldType): string {
  switch (type) {
    case "FT_BOOLEAN":
      return "boolean";
    case "FT_IPv4":
      return "IPv4 address";
    case "FT_IPv6":
      return "IPv6 address";
    case "FT_ETHER":
      return "MAC address";
    case "FT_RELATIVE_TIME":
      return "time";
    case "FT_NONE":
      return "label";
    default:
      return "number";
  }
}

function regex(v: Token): RegExp {
  let source = v.value;
  let flags = "";
  const m = /^\(\?([imsx]+)\)/.exec(source);
  if (m) {
    source = source.slice(m[0].length);
    flags = [...new Set(m[1].replace("x", ""))].join("");
  }
  try {
    return new RegExp(source, flags);
  } catch (err) {
    throw new BasicFilterError(`The regular expression is invalid: ${(err as Error).message}.`, [
      v.start,
      v.end,
    ]);
  }
}

function parseUint(text: string): number | null {
  if (/^\d+$/.test(text)) {
    return Number(text);
  }
  if (/^0x[0-9a-fA-F]+$/.test(text)) {
    return parseInt(text.slice(2), 16);
  }
  return null;
}

/** An IPv4 address as a 32-bit number, or null. */
export function ipv4Number(text: string): number | null {
  const parts = text.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) {
    return null;
  }
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

function parseNet4(text: string): Literal | null {
  const [addr, bits, extra] = text.split("/");
  const n = ipv4Number(addr);
  if (n === null || extra !== undefined) {
    return null;
  }
  const b = bits === undefined ? 32 : /^\d+$/.test(bits) ? Number(bits) : -1;
  if (b < 0 || b > 32) {
    return null;
  }
  const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
  return { kind: "net4", addr: (n & mask) >>> 0, mask };
}

/** An IPv6 address as a 128-bit number, or null (also "::ffff:1.2.3.4"). */
export function ipv6Number(text: string): bigint | null {
  let s = text.toLowerCase();
  const v4 = /:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    const n = ipv4Number(v4[1]);
    if (n === null) {
      return null;
    }
    s = `${s.slice(0, v4.index)}:${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) {
    return null;
  }
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    return null;
  }
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
    return null;
  }
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function parseNet6(text: string): Literal | null {
  const [addr, bits, extra] = text.split("/");
  const n = ipv6Number(addr);
  if (n === null || extra !== undefined) {
    return null;
  }
  const b = bits === undefined ? 128 : /^\d+$/.test(bits) ? Number(bits) : -1;
  if (b < 0 || b > 128) {
    return null;
  }
  return { kind: "net6", addr: n >> BigInt(128 - b), bits: b };
}

/** A MAC address in lower case with colons ("aa:bb:cc:dd:ee:ff"), from any common form. */
export function normalizeMac(text: string): string | null {
  const hex = text.replace(/[:.-]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) {
    return null;
  }
  const parts = text.split(/[:.-]/);
  if (!(parts.length === 6 || parts.length === 3 || parts.length === 1)) {
    return null;
  }
  return hex.match(/../g)!.join(":");
}

// -- evaluation --------------------------------------------------------------------------

/** Parse and check `expr`; throws BasicFilterError. */
export function compileBasicFilter(expr: string): Node {
  return new Parser(expr, tokenize(expr)).parse();
}

/** The field and protocol names `node` reads. */
export function filterNames(node: Node, out = new Set<string>()): Set<string> {
  switch (node.op) {
    case "and":
    case "or":
    case "xor":
      filterNames(node.left, out);
      filterNames(node.right, out);
      break;
    case "not":
      filterNames(node.arg, out);
      break;
    default:
      out.add(node.field);
  }
  return out;
}

/** A packet's values of a field (none: an empty list). */
export type Values = (name: string) => FieldValue[];

function asNumber(type: FieldType, v: FieldValue): number | bigint | null {
  if (typeof v === "number") {
    return v;
  }
  if (Buffer.isBuffer(v)) {
    return null;
  }
  switch (type) {
    case "FT_IPv4":
      return ipv4Number(v);
    case "FT_IPv6":
      return ipv6Number(v);
    default: {
      const n = parseUint(v) ?? Number(v);
      return Number.isFinite(n) ? n : null;
    }
  }
}

function equal(type: FieldType, v: FieldValue, lit: Literal): boolean {
  switch (lit.kind) {
    case "net4": {
      const n = asNumber(type, v);
      return typeof n === "number" && (n & lit.mask) >>> 0 === lit.addr;
    }
    case "net6": {
      const n = asNumber(type, v);
      return typeof n === "bigint" && n >> BigInt(128 - lit.bits) === lit.addr;
    }
    case "ether":
      return typeof v === "string" && v.toLowerCase() === lit.value;
    case "string":
      return typeof v === "string" && v === lit.value;
    case "bytes":
      return Buffer.isBuffer(v) && v.equals(lit.value);
    case "number":
      return asNumber(type, v) === lit.value;
  }
}

function order(type: FieldType, v: FieldValue, lit: Literal): number | null {
  let a: number | bigint | string | null;
  let b: number | bigint | string;
  switch (lit.kind) {
    case "number":
      a = asNumber(type, v);
      b = lit.value;
      break;
    case "net4":
      a = asNumber(type, v);
      b = lit.addr;
      break;
    case "net6": {
      a = asNumber(type, v);
      b = lit.addr << BigInt(128 - lit.bits);
      break;
    }
    case "ether":
    case "string":
      a = typeof v === "string" ? v.toLowerCase() : null;
      b = lit.value;
      break;
    default:
      a = Buffer.isBuffer(v) ? v.toString("hex") : null;
      b = lit.value.toString("hex");
  }
  if (a === null || typeof a !== typeof b) {
    return null;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function relate(type: FieldType, v: FieldValue, rel: Relation, lit: Literal): boolean {
  if (rel === "any_eq" || rel === "all_eq") {
    return equal(type, v, lit);
  }
  if (rel === "all_ne" || rel === "any_ne") {
    return !equal(type, v, lit);
  }
  const c = order(type, v, lit);
  if (c === null) {
    return false;
  }
  return rel === "gt" ? c > 0 : rel === "lt" ? c < 0 : rel === "ge" ? c >= 0 : c <= 0;
}

function text(v: FieldValue): string {
  return Buffer.isBuffer(v) ? v.toString("latin1") : String(v);
}

/** Whether a packet whose fields `values` gives matches `node`. */
export function matchesFilter(node: Node, values: Values): boolean {
  switch (node.op) {
    case "and":
      return matchesFilter(node.left, values) && matchesFilter(node.right, values);
    case "or":
      return matchesFilter(node.left, values) || matchesFilter(node.right, values);
    case "xor":
      return matchesFilter(node.left, values) !== matchesFilter(node.right, values);
    case "not":
      return !matchesFilter(node.arg, values);
    case "exists":
      return values(node.field).length > 0;
    case "compare": {
      const vs = values(node.field);
      if (!vs.length) {
        return false;
      }
      const test = (v: FieldValue) => relate(node.type, v, node.rel, node.value);
      return node.rel === "all_eq" || node.rel === "all_ne" ? vs.every(test) : vs.some(test);
    }
    case "contains":
      return values(node.field).some((v) =>
        typeof node.value === "string"
          ? text(v).includes(node.value)
          : Buffer.isBuffer(v)
            ? v.includes(node.value)
            : Buffer.from(text(v), "latin1").includes(node.value),
      );
    case "matches":
      return values(node.field).some((v) => node.regex.test(text(v)));
    case "in":
      return values(node.field).some((v) =>
        node.items.some((item) =>
          item.hi
            ? relate(node.type, v, "ge", item.lo) && relate(node.type, v, "le", item.hi)
            : equal(node.type, v, item.lo),
        ),
      );
  }
}

/**
 * Fields for autocomplete (`field_index` with a prefix): protocols and
 * fields whose names start with `prefix` (any case), sorted by name.
 */
export function searchBasicFields(
  prefix: string,
  limit: number,
): { protocols: { name: string; desc: string }[]; fields: BasicField[]; truncated: boolean } {
  const p = prefix.toLowerCase();
  const protocols = BASIC_PROTOCOLS.filter((x) => x.name.startsWith(p)).slice(0, limit);
  const all = BASIC_FIELDS.filter((x) => x.name.toLowerCase().startsWith(p));
  return { protocols, fields: all.slice(0, limit), truncated: all.length > limit };
}

/**
 * Fields for the filter builder (`field_index` with words): every word in
 * the name or description; exact names first, then name prefixes.
 */
export function findBasicFields(
  words: string,
  limit: number,
): (BasicField | { name: string; desc: string; type: "protocol" })[] {
  const ws = words.toLowerCase().split(/\s+/).filter(Boolean);
  if (!ws.length) {
    return [];
  }
  const q = words.trim().toLowerCase();
  const entries = [
    ...BASIC_PROTOCOLS.map((p) => ({ ...p, type: "protocol" as const })),
    ...BASIC_FIELDS,
  ].filter((e) => ws.every((w) => `${e.name}\t${e.desc}`.toLowerCase().includes(w)));
  const rank = (e: { name: string }) =>
    e.name === q
      ? 0
      : e.name.startsWith(q)
        ? 1
        : e.name.split(".").includes(q)
          ? 2
          : e.name.includes(q)
            ? 3
            : 4;
  return entries.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name)).slice(0, limit);
}
