/**
 * The basic view: a capture read without Python or tshark, so a first look
 * works before the tools are installed. Pure Node (no `vscode` import): pcap
 * and pcapng (also gzip-compressed) are indexed here and each packet's
 * link, network and transport headers decoded, with a first look at DNS,
 * HTTP and TLS. Everything else (filters, statistics, follow…) needs tshark.
 *
 * The shapes match the backend's (`list_packets` rows, `packet_detail`'s
 * tree and byte sources), so the viewer shows them unchanged.
 */
import * as fs from "node:fs";
import { promisify } from "node:util";
import * as zlib from "node:zlib";
import {
  BASIC_FIELDS,
  BASIC_PROTOCOLS,
  BasicFilterError,
  basicFieldType,
  compileBasicFilter,
  filterNames,
  findBasicFields,
  matchesFilter,
  searchBasicFields,
  type FieldValue,
  type Node as FilterNode,
  type Values,
} from "./basicFilter";

/** A gzip-compressed capture is unpacked in memory up to this size. */
export const MAX_GUNZIP_BYTES = 512 * 1024 * 1024;
/** Larger packets mean a damaged file (tshark's limit for pcapng, 256 KiB). */
const MAX_PACKET = 262_144;
const CHUNK = 4 * 1024 * 1024;
const YIELD_EVERY = 20_000;
const gunzip = promisify(zlib.gunzip);
const breather = () => new Promise<void>((resolve) => setImmediate(resolve));

/** One node of a detail tree, as the backend sends them. */
export interface TreeNode {
  id: number;
  label: string;
  name?: string;
  show?: string;
  pos?: number;
  size?: number;
  src: number;
  proto?: boolean;
  children?: TreeNode[];
}

export interface BasicRow {
  number: number;
  /** No., Time, Source, Destination, Protocol, Length, Info (as strings). */
  cells: string[];
}

export class CaptureFormatError extends Error {}

/** A request the basic view can't answer: it needs the full viewer (tshark). */
export class NeedsToolsError extends Error {
  constructor(what: string) {
    super(`${what} needs tshark: install Wireshark (and Python) and reload to use it.`);
  }
}

/** The seven base columns, as the backend describes them at open. */
export const BASIC_COLUMNS = [
  { id: "number", title: "No.", field: "frame.number", numeric: true },
  { id: "time", title: "Time", field: "frame.time_relative", numeric: true },
  { id: "source", title: "Source", field: "_ws.col.def_src", numeric: false },
  { id: "destination", title: "Destination", field: "_ws.col.def_dst", numeric: false },
  { id: "protocol", title: "Protocol", field: "_ws.col.protocol", numeric: false },
  { id: "length", title: "Length", field: "frame.len", numeric: true },
  { id: "info", title: "Info", field: "_ws.col.info", numeric: false },
];

/** The view `open` describes: every packet, in capture order. */
const FILTER_ID = 1;
const MAX_PAGE = 5000;
/** A filter pass yields to the event loop (and checks for a cancel) this often. */
const FILTER_YIELD = 2000;
/** Filter results kept, by expression. */
const MAX_CACHED_FILTERS = 8;

/** Where the bytes come from: the file (read in place) or a gunzipped copy in memory. */
interface Source {
  size: number;
  read(offset: number, length: number): Buffer;
  close(): void;
}

function fileSource(path: string): Source {
  const fd = fs.openSync(path, "r");
  return {
    size: fs.fstatSync(fd).size,
    read(offset, length) {
      const out = Buffer.alloc(length);
      let done = 0;
      while (done < length) {
        const n = fs.readSync(fd, out, done, length - done, offset + done);
        if (n === 0) {
          break;
        }
        done += n;
      }
      return done === length ? out : out.subarray(0, done);
    },
    close() {
      fs.closeSync(fd);
    },
  };
}

function memorySource(data: Buffer): Source {
  return {
    size: data.length,
    read: (offset, length) => data.subarray(offset, offset + length),
    close: () => undefined,
  };
}

/** Sequential reads over a source, in chunks (records may cross a chunk's end). */
class Window {
  private buf: Buffer = Buffer.alloc(0);
  private start = 0;
  constructor(private readonly source: Source) {}
  /** `length` bytes at `offset`, or fewer at the end of the file. */
  get(offset: number, length: number): Buffer {
    const end = offset + length;
    if (offset < this.start || end > this.start + this.buf.length) {
      this.start = offset;
      this.buf = this.source.read(offset, Math.max(length, CHUNK));
    }
    return this.buf.subarray(offset - this.start, Math.min(end - this.start, this.buf.length));
  }
}

const LINK_TYPES: Record<number, string> = {
  0: "BSD loopback",
  1: "Ethernet",
  12: "Raw IP",
  14: "Raw IP",
  101: "Raw IP",
  105: "IEEE 802.11",
  108: "OpenBSD loopback",
  113: "Linux cooked capture v1",
  127: "IEEE 802.11 plus radiotap",
  228: "Raw IPv4",
  229: "Raw IPv6",
  276: "Linux cooked capture v2",
};

interface Interface {
  linkType: number;
  /** Timestamp units per second (pcapng if_tsresol; default microseconds). */
  units: bigint;
  /** if_tsoffset, seconds. */
  offset: bigint;
  /** The interface's snap length (0: none). */
  snapLen: number;
}

/** A capture indexed in memory: where each packet is, its lengths, link type and time. */
export class BasicCapture {
  readonly offsets: number[] = [];
  readonly capLens: number[] = [];
  readonly origLens: number[] = [];
  readonly linkTypes: number[] = [];
  /** Seconds and nanoseconds since the epoch (null: the record has no time). */
  readonly seconds: (number | null)[] = [];
  readonly nanos: number[] = [];
  readonly warnings: string[] = [];
  fileType = "";
  /** The list's view: every packet (`frames` null) or a filter's matches, in capture order. */
  view: { filterId: number; expr: string; frames: Uint32Array | null } = {
    filterId: FILTER_ID,
    expr: "",
    frames: null,
  };
  /** Marked and ignored packets (the session's, as the backend keeps them). */
  readonly marks = new Set<number>();
  readonly ignored = new Set<number>();
  private readonly filters = new Map<string, Uint32Array>();
  private filterSeq = 0;

  private constructor(
    readonly path: string,
    private readonly source: Source,
    readonly compressed: boolean,
  ) {}

  /**
   * Index a pcap or pcapng file, gzip-compressed or not. The pass yields to
   * the event loop every YIELD_EVERY packets, so a large file doesn't hold up
   * the extension host.
   */
  static async open(path: string, maxGunzip = MAX_GUNZIP_BYTES): Promise<BasicCapture> {
    const head = fileSource(path);
    let magic: Buffer;
    try {
      magic = head.read(0, 4);
    } catch (err) {
      head.close();
      throw err;
    }
    if (magic.length < 4) {
      head.close();
      throw new CaptureFormatError("the file is empty or too short to be a capture");
    }
    let source = head;
    let compressed = false;
    if (magic[0] === 0x1f && magic[1] === 0x8b) {
      head.close();
      let data: Buffer;
      try {
        data = await gunzip(await fs.promises.readFile(path), { maxOutputLength: maxGunzip });
      } catch (err) {
        if (
          err instanceof RangeError ||
          (err as { code?: string }).code === "ERR_BUFFER_TOO_LARGE"
        ) {
          throw new CaptureFormatError(
            `it unpacks to more than ${maxGunzip / 1024 / 1024} MB, too much to read without tshark`,
          );
        }
        throw new CaptureFormatError(`it isn't a valid gzip file (${(err as Error).message})`);
      }
      source = memorySource(data);
      compressed = true;
    } else if (magic.readUInt32BE(0) === 0x28b52ffd || magic.readUInt32LE(0) === 0x184d2204) {
      head.close();
      throw new CaptureFormatError("zstd and lz4 compressed captures need tshark");
    }
    const capture = new BasicCapture(path, source, compressed);
    try {
      await capture.index();
    } catch (err) {
      source.close();
      throw err;
    }
    return capture;
  }

  get count(): number {
    return this.offsets.length;
  }

  get size(): number {
    return this.source.size;
  }

  close(): void {
    this.source.close();
  }

  /** The packet's captured bytes (1-based number). */
  bytes(number: number): Buffer {
    const i = number - 1;
    return this.source.read(this.offsets[i], this.capLens[i]);
  }

  private async index(): Promise<void> {
    const w = new Window(this.source);
    const head = w.get(0, 24);
    if (head.length < 4) {
      throw new CaptureFormatError("the file is empty or too short to be a capture");
    }
    const be = head.readUInt32BE(0);
    if (be === 0x0a0d0d0a) {
      this.fileType = "pcapng";
      await this.indexPcapng(w);
    } else if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(be)) {
      this.fileType = "pcap";
      await this.indexPcap(w, head);
    } else {
      throw new CaptureFormatError("it isn't a pcap or pcapng file (other formats need tshark)");
    }
  }

  private add(
    offset: number,
    capLen: number,
    origLen: number,
    linkType: number,
    sec: number | null,
    nsec: number,
  ): void {
    this.offsets.push(offset);
    this.capLens.push(capLen);
    this.origLens.push(origLen);
    this.linkTypes.push(linkType);
    this.seconds.push(sec);
    this.nanos.push(nsec);
  }

  private stop(message: string): void {
    this.warnings.push(
      `${message}; the ${this.count.toLocaleString("en-US")} packets before it are shown.`,
    );
  }

  private async indexPcap(w: Window, head: Buffer): Promise<void> {
    if (head.length < 24) {
      throw new CaptureFormatError("the pcap header is cut short");
    }
    const le = head.readUInt32LE(0) === 0xa1b2c3d4 || head.readUInt32LE(0) === 0xa1b23c4d;
    const nano = (le ? head.readUInt32LE(0) : head.readUInt32BE(0)) === 0xa1b23c4d;
    const u32 = (b: Buffer, o: number) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
    // The link type's low 16 bits (the upper ones carry FCS flags).
    const linkType = u32(head, 20) & 0xffff;
    let pos = 24;
    while (pos < this.source.size) {
      if (this.count % YIELD_EVERY === YIELD_EVERY - 1) {
        await breather();
      }
      const rec = w.get(pos, 16);
      if (rec.length < 16) {
        this.stop(`The file ends inside a packet header at byte ${pos}`);
        return;
      }
      const capLen = u32(rec, 8);
      if (capLen > MAX_PACKET) {
        this.stop(
          `Packet ${this.count + 1} claims ${capLen} bytes (more than 256 KB) at byte ${pos}`,
        );
        return;
      }
      if (pos + 16 + capLen > this.source.size) {
        this.stop(`The file ends inside packet ${this.count + 1}`);
        return;
      }
      const frac = u32(rec, 4);
      this.add(pos + 16, capLen, u32(rec, 12), linkType, u32(rec, 0), nano ? frac : frac * 1000);
      pos += 16 + capLen;
    }
  }

  private async indexPcapng(w: Window): Promise<void> {
    let pos = 0;
    let le = true;
    let interfaces: Interface[] = [];
    while (pos < this.source.size) {
      if (this.count % YIELD_EVERY === YIELD_EVERY - 1) {
        await breather();
      }
      const head = w.get(pos, 12);
      if (head.length < 8) {
        this.stop(`The file ends inside a block header at byte ${pos}`);
        return;
      }
      const type = head.readUInt32LE(0);
      if (type === 0x0a0d0d0a) {
        if (head.length < 12) {
          this.stop(`The file ends inside a section header at byte ${pos}`);
          return;
        }
        le = head.readUInt32LE(8) === 0x1a2b3c4d;
        interfaces = [];
      }
      const u32 = (b: Buffer, o: number) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
      const u16 = (b: Buffer, o: number) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
      const blockType = u32(head, 0);
      const length = u32(head, 4);
      if (length < 12 || length % 4 !== 0) {
        this.stop(`A block at byte ${pos} has a wrong length (${length})`);
        return;
      }
      if (pos + length > this.source.size) {
        this.stop(`A block at byte ${pos} goes past the end of the file`);
        return;
      }
      if (length > MAX_PACKET + 1024 && (blockType === 6 || blockType === 3 || blockType === 2)) {
        this.stop(`A packet block at byte ${pos} is ${length} bytes long (more than 256 KB)`);
        return;
      }
      const body = () => w.get(pos + 8, length - 12);
      if (blockType === 1) {
        const b = body();
        interfaces.push(readInterface(b, u16, u32, le));
      } else if (blockType === 6 || blockType === 2) {
        // Enhanced (6) and the obsolete Packet block (2): interface, time, lengths.
        const b = w.get(pos + 8, 20);
        const id = blockType === 6 ? u32(b, 0) : u16(b, 0);
        const iface = interfaces[id];
        const capLen = u32(b, 12);
        if (!iface || capLen > length - 32) {
          this.stop(`A packet at byte ${pos} names an unknown interface or a wrong length`);
          return;
        }
        const ticks = (BigInt(u32(b, 4)) << 32n) | BigInt(u32(b, 8));
        const total = (ticks * 1_000_000_000n) / iface.units + iface.offset * 1_000_000_000n;
        this.add(
          pos + 28,
          capLen,
          u32(b, 16),
          iface.linkType,
          Number(total / 1_000_000_000n),
          Number(total % 1_000_000_000n),
        );
      } else if (blockType === 3) {
        // Simple packet block: no time, the first interface.
        const b = w.get(pos + 8, 4);
        const orig = u32(b, 0);
        const iface = interfaces[0];
        if (!iface) {
          this.stop(`A packet at byte ${pos} comes before any interface`);
          return;
        }
        // Captured = the original length cut at the snap length; the block's
        // own length counts its padding too (Codex review).
        const snap = iface.snapLen > 0 ? iface.snapLen : Infinity;
        this.add(pos + 12, Math.min(orig, snap, length - 16), orig, iface.linkType, null, 0);
      }
      pos += length;
    }
  }

  /** The capture's first and last packet times (epoch seconds), when known. */
  timeSpan(): { start: number | null; end: number | null } {
    let start: number | null = null;
    let end: number | null = null;
    for (let i = 0; i < this.count; i++) {
      const s = this.seconds[i];
      if (s === null) {
        continue;
      }
      const t = s + this.nanos[i] / 1e9;
      start = start === null ? t : Math.min(start, t);
      end = end === null ? t : Math.max(end, t);
    }
    return { start, end };
  }

  /** "Ethernet", "Raw IP"… or "Several" when the interfaces differ. */
  linkTypeName(): string | null {
    const types = new Set(this.linkTypes);
    if (types.size > 1) {
      return "Several";
    }
    const [only] = types;
    return only === undefined ? null : (LINK_TYPES[only] ?? `Link type ${only}`);
  }

  /** Packet `number`'s time in nanoseconds since the epoch (null: not recorded). */
  epochNs(number: number): bigint | null {
    const s = this.seconds[number - 1];
    return s === null || s === undefined ? null : BigInt(s) * NS + BigInt(this.nanos[number - 1]);
  }

  /** Seconds since the first timed packet, as the full viewer shows them ("0.000123"). */
  relativeTime(number: number): string {
    const ns = this.epochNs(number);
    const first = this.firstTime();
    return ns === null || first === null ? "" : formatSeconds(ns - first);
  }

  /**
   * The Time column in `format` (the backend's TIME_FORMATS), measured from
   * packet `ref` when given (its own row says *REF*). "Since previous
   * displayed" is since `previousShown` (the view's packet before this one).
   */
  timeText(
    number: number,
    format: string,
    ref: number | null,
    previousShown: number | null = number - 1,
  ): string {
    if (!TIME_FORMATS.includes(format)) {
      throw new RangeError(`timeFormat must be one of ${TIME_FORMATS.join(", ")}`);
    }
    if (number === ref) {
      return "*REF*";
    }
    const ns = this.epochNs(number);
    if (ns === null) {
      return "";
    }
    switch (format) {
      case "relative": {
        const from = ref === null ? this.firstTime() : this.epochNs(ref);
        return from === null ? "" : formatSeconds(ns - from);
      }
      case "delta_displayed":
      case "delta_captured": {
        const before = format === "delta_captured" ? number - 1 : previousShown;
        const prev = before !== null && before >= 1 ? this.epochNs(before) : null;
        return formatSeconds(prev === null ? 0n : ns - prev);
      }
      case "epoch":
        return formatSeconds(ns);
      default:
        return formatAbsolute(ns, format === "utc");
    }
  }

  private first?: bigint | null;
  private firstTime(): bigint | null {
    if (this.first === undefined) {
      const i = this.seconds.findIndex((s) => s !== null);
      this.first = i < 0 ? null : this.epochNs(i + 1);
    }
    return this.first;
  }

  /** Packets in the view. */
  get viewCount(): number {
    return this.view.frames ? this.view.frames.length : this.count;
  }

  /** The view's packet at `index`. */
  private viewFrame(index: number): number {
    return this.view.frames ? this.view.frames[index] : index + 1;
  }

  /** `limit` packets of the view from `offset`. */
  viewSlice(offset: number, limit: number): number[] {
    const out: number[] = [];
    for (let i = offset; i < Math.min(this.viewCount, offset + limit); i++) {
      out.push(this.viewFrame(i));
    }
    return out;
  }

  /** Packet `number`'s position in the view, or -1. */
  indexOf(number: number): number {
    const frames = this.view.frames;
    if (!frames) {
      return Number.isInteger(number) && number >= 1 && number <= this.count ? number - 1 : -1;
    }
    let lo = 0;
    let hi = frames.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (frames[mid] < number) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return frames[lo] === number ? lo : -1;
  }

  /** The view's packet before packet `number` (in capture order), or null. */
  previousShown(number: number): number | null {
    const frames = this.view.frames;
    if (!frames) {
      return number > 1 ? number - 1 : null;
    }
    let lo = 0;
    let hi = frames.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (frames[mid] < number) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo > 0 ? frames[lo - 1] : null;
  }

  /**
   * Packet `number`'s fields for filters. The packet is dissected only when
   * a field outside the frame's own is asked for, and then collects only
   * `wanted` (every field when absent).
   */
  values(number: number, wanted?: ReadonlySet<string>): Values {
    const i = number - 1;
    let fields: Map<string, FieldValue[]> | undefined;
    let row: Dissected | undefined;
    const dissected = (): { fields: Map<string, FieldValue[]>; row: Dissected } => {
      if (!fields || !row) {
        fields = new Map();
        row = dissect(this.bytes(number), this.linkTypes[i], false, fields, wanted);
      }
      return { fields, row };
    };
    return (name) => {
      switch (name) {
        case "frame":
          return [this.bytes(number)];
        case "frame.number":
          return [number];
        case "frame.len":
          return [this.origLens[i]];
        case "frame.cap_len":
          return [this.capLens[i]];
        case "frame.time_relative": {
          const t = this.relativeTime(number);
          return t ? [Number(t)] : [];
        }
        case "_ws.col.protocol":
          return [dissected().row.protocol];
        case "_ws.col.info":
          return [dissected().row.info];
        case "_ws.col.def_src":
          return [dissected().row.src];
        case "_ws.col.def_dst":
          return [dissected().row.dst];
        default:
          return dissected().fields.get(name) ?? [];
      }
    };
  }

  /** The packets (of `frames`, else the whole capture) matching `filter`. */
  private async matching(
    filter: FilterNode,
    ctx: BasicRequestContext,
    phase: string,
    seq?: number,
  ): Promise<Uint32Array> {
    const out = new Uint32Array(this.count);
    const wanted = filterNames(filter);
    let n = 0;
    for (let number = 1; number <= this.count; number++) {
      if (number % FILTER_YIELD === 0) {
        ctx.progress?.(number / this.count, phase);
        await breather();
        if (ctx.cancelled || (seq !== undefined && seq !== this.filterSeq)) {
          throw new BasicCancelledError();
        }
      }
      if (matchesFilter(filter, this.values(number, wanted))) {
        out[n++] = number;
      }
    }
    return out.slice(0, n);
  }

  /** Apply display filter `expr` ("" = every packet): `set_filter`'s answer. */
  async setFilter(
    expr: string,
    ctx: BasicRequestContext,
  ): Promise<{ expr: string; matchCount: number; total: number; filterId: number }> {
    const seq = ++this.filterSeq;
    let frames: Uint32Array | null = null;
    if (expr) {
      frames = this.filters.get(expr) ?? null;
      if (!frames) {
        try {
          frames = await this.matching(compileBasicFilter(expr), ctx, "filter", seq);
        } catch (err) {
          if (err instanceof BasicFilterError && ctx.cancelled) {
            throw new BasicCancelledError();
          }
          throw err;
        }
        this.filters.delete(expr);
        this.filters.set(expr, frames);
        while (this.filters.size > MAX_CACHED_FILTERS) {
          this.filters.delete(this.filters.keys().next().value as string);
        }
      }
    }
    if (seq !== this.filterSeq) {
      throw new BasicCancelledError();
    }
    this.view = { filterId: this.view.filterId + 1, expr, frames };
    return {
      expr,
      matchCount: this.viewCount,
      total: this.count,
      filterId: this.view.filterId,
    };
  }

  /**
   * Find Packet: the next (or previous) packet of the view after `from` that
   * matches, wrapping around. Modes as the backend's: a display filter, text
   * or a regular expression in the bytes, the list's cells or the details,
   * hex bytes, or the marked packets.
   */
  async findPacket(
    params: Record<string, unknown>,
    ctx: BasicRequestContext,
  ): Promise<{ frame: number | null; index: number | null; filterId: number; wrapped?: boolean }> {
    const mode = String(params.mode ?? "");
    const where = String(params.in ?? "bytes");
    const value = String(params.value ?? "");
    const filterId = this.view.filterId;
    if (!["filter", "string", "regex", "hex", "marked"].includes(mode)) {
      throw new RangeError("invalid find mode");
    }
    if (!["bytes", "list", "details"].includes(where)) {
      throw new RangeError("in must be one of bytes, list, details");
    }
    const test = this.findTest(mode, where, value, params.caseSensitive === true);
    const total = this.viewCount;
    const direction = params.direction === "previous" ? -1 : 1;
    const from = typeof params.from === "number" ? this.indexOf(params.from) : -1;
    let index = from < 0 ? (direction > 0 ? -1 : total) : from;
    let wrapped = false;
    for (let step = 0; step < total; step++) {
      index += direction;
      if (index >= total || index < 0) {
        index = direction > 0 ? 0 : total - 1;
        wrapped = from >= 0;
      }
      if (step > 0 && step % FILTER_YIELD === 0) {
        ctx.progress?.(step / total, "find");
        await breather();
        if (ctx.cancelled) {
          throw new BasicCancelledError();
        }
      }
      const frame = this.viewFrame(index);
      if (test(frame)) {
        return { frame, index, filterId, wrapped };
      }
    }
    return { frame: null, index: null, filterId };
  }

  private findTest(
    mode: string,
    where: string,
    value: string,
    caseSensitive: boolean,
  ): (frame: number) => boolean {
    if (mode === "marked") {
      return (n) => this.marks.has(n);
    }
    if (mode === "filter") {
      const filter = compileBasicFilter(value);
      const wanted = filterNames(filter);
      return (n) => matchesFilter(filter, this.values(n, wanted));
    }
    if (!value) {
      throw new RangeError("value is empty");
    }
    if (mode === "hex") {
      const hex = value.replace(/[\s:.-]/g, "");
      if (!/^([0-9a-fA-F]{2})+$/.test(hex)) {
        throw new RangeError(`"${value}" isn't hex bytes (such as 47 45 54)`);
      }
      const bytes = Buffer.from(hex, "hex");
      return (n) => this.bytes(n).includes(bytes);
    }
    let pattern: RegExp;
    try {
      pattern =
        mode === "regex"
          ? new RegExp(value, caseSensitive ? "m" : "im")
          : new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), caseSensitive ? "" : "i");
    } catch (err) {
      throw new BasicFilterError(
        `The regular expression is invalid: ${(err as Error).message}.`,
        null,
      );
    }
    switch (where) {
      case "list":
        return (n) => pattern.test(this.row(n).cells.slice(2).join("\n"));
      case "details":
        return (n) => {
          const lines: string[] = [];
          const walk = (nodes: TreeNode[]) => {
            for (const node of nodes) {
              lines.push(node.label.replace(/^\[(.*)\]$/, "$1"));
              walk(node.children ?? []);
            }
          };
          walk(this.detail(n).tree);
          return pattern.test(lines.join("\n"));
        };
      default: {
        // (The backend's bytes search is tshark's `frame contains/matches` on the UTF-8 text.)
        if (mode === "string" && caseSensitive) {
          const needle = Buffer.from(value, "utf8");
          return (n) => this.bytes(n).includes(needle);
        }
        const bytesPattern = new RegExp(
          Buffer.from(pattern.source, "utf8").toString("latin1"),
          pattern.flags,
        );
        return (n) => bytesPattern.test(this.bytes(n).toString("latin1"));
      }
    }
  }

  /** The filter builder's values of `field` (in packets matching `filter`), most frequent first. */
  async fieldValues(
    field: string,
    filter: string,
    limit: number,
    ctx: BasicRequestContext,
  ): Promise<Record<string, unknown>> {
    const type = basicFieldType(field);
    if (type === undefined) {
      throw new RangeError(`${field} isn't a field the basic view reads`);
    }
    const scope = filter ? compileBasicFilter(filter) : null;
    const wanted = new Set([field, ...(scope ? filterNames(scope) : [])]);
    const counts = new Map<string, number>();
    let packets = 0;
    let more = 0;
    for (let number = 1; number <= this.count; number++) {
      if (number % FILTER_YIELD === 0) {
        ctx.progress?.(number / this.count, "values");
        await breather();
        if (ctx.cancelled) {
          throw new BasicCancelledError();
        }
      }
      const values = this.values(number, wanted);
      if (scope && !matchesFilter(scope, values)) {
        continue;
      }
      const list = values(field);
      if (!list.length || type === "FT_PROTOCOL" || type === "FT_NONE") {
        packets += list.length ? 1 : 0;
        continue;
      }
      packets++;
      for (const text of new Set(list.map(valueText))) {
        const c = counts.get(text);
        if (c !== undefined) {
          counts.set(text, c + 1);
        } else if (counts.size < MAX_DISTINCT) {
          counts.set(text, 1);
        } else {
          more++;
        }
      }
    }
    const values = [...counts]
      .map(([value, count]) => ({ value, count }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
    return {
      field,
      type,
      values: values.slice(0, limit),
      packets,
      distinct: counts.size,
      more,
      ...(filter ? { filter } : {}),
    };
  }

  /** Why `expr` may match nothing: which of its fields occur in no packet. */
  async filterHints(expr: string, ctx: BasicRequestContext): Promise<Record<string, unknown>> {
    if (!expr) {
      throw new RangeError("expr is empty");
    }
    const names = [...filterNames(compileBasicFilter(expr))]
      .filter((n) => n !== "frame" && !n.startsWith("frame.") && !n.startsWith("_ws.col."))
      .slice(0, MAX_HINT_FIELDS);
    const present = new Set<string>();
    const wanted = new Set(names);
    for (let number = 1; number <= this.count && present.size < names.length; number++) {
      if (number % FILTER_YIELD === 0) {
        await breather();
        if (ctx.cancelled) {
          throw new BasicCancelledError();
        }
      }
      const values = this.values(number, wanted);
      for (const name of names) {
        if (!present.has(name) && values(name).length) {
          present.add(name);
        }
      }
    }
    return {
      expr,
      fields: names.map((name) => ({ name, present: present.has(name) })),
      caseHints: [],
    };
  }

  /** The packet list's row of packet `number`. */
  row(number: number): BasicRow {
    const i = number - 1;
    const d = dissect(this.bytes(number), this.linkTypes[i], false);
    return {
      number,
      cells: [
        String(number),
        this.relativeTime(number),
        d.src,
        d.dst,
        d.protocol,
        String(this.origLens[i]),
        d.info,
      ],
    };
  }

  /** `packet_detail`'s answer: the tree (Frame first) and the packet's bytes. */
  detail(number: number): {
    number: number;
    tree: TreeNode[];
    sources: { name: string; hex: string }[];
  } {
    const i = number - 1;
    const data = this.bytes(number);
    const d = dissect(data, this.linkTypes[i], true);
    const ids = { next: d.nextId };
    const frame = node(ids, {
      label:
        `Frame ${number}: ${this.origLens[i]} bytes on wire (${this.origLens[i] * 8} bits), ` +
        `${this.capLens[i]} bytes captured (${this.capLens[i] * 8} bits)`,
      name: "frame",
      pos: 0,
      size: data.length,
      proto: true,
    });
    frame.children = [
      node(ids, {
        label: `Arrival Time: ${this.arrival(i)}`,
        name: "frame.time",
      }),
      node(ids, {
        label: `Time since the first packet: ${this.relativeTime(number)} seconds`,
        name: "frame.time_relative",
      }),
      node(ids, { label: `Frame Number: ${number}`, name: "frame.number", show: String(number) }),
      node(ids, {
        label: `Frame Length: ${this.origLens[i]} bytes`,
        name: "frame.len",
        show: String(this.origLens[i]),
      }),
      node(ids, {
        label: `Capture Length: ${this.capLens[i]} bytes`,
        name: "frame.cap_len",
        show: String(this.capLens[i]),
      }),
      node(ids, {
        label: `Encapsulation type: ${LINK_TYPES[this.linkTypes[i]] ?? `Link type ${this.linkTypes[i]}`}`,
      }),
    ];
    return {
      number,
      tree: [frame, ...d.tree],
      sources: [{ name: "Frame", hex: data.toString("hex") }],
    };
  }

  private arrival(i: number): string {
    const s = this.seconds[i];
    if (s === null) {
      return "not recorded";
    }
    const date = new Date(s * 1000);
    return `${date.toISOString().slice(0, 19).replace("T", " ")}.${String(this.nanos[i]).padStart(9, "0")} UTC`;
  }
}

const NS = 1_000_000_000n;
/** The Time column's formats, as the backend names them (navigation.TIME_FORMATS). */
export const TIME_FORMATS = [
  "relative",
  "delta_displayed",
  "delta_captured",
  "absolute",
  "utc",
  "epoch",
];

/** Seconds with microsecond precision, as the backend's format_seconds: "-0.000123". */
export function formatSeconds(ns: bigint): string {
  const abs = ns < 0n ? -ns : ns;
  const micro = (abs % NS) / 1000n;
  return `${ns < 0n ? "-" : ""}${abs / NS}.${micro.toString().padStart(6, "0")}`;
}

/** "2023-11-14 22:13:20.000000" in the local time zone or UTC (format_absolute). */
export function formatAbsolute(ns: bigint, utc: boolean): string {
  const sec = ns >= 0n ? ns / NS : -((-ns + NS - 1n) / NS);
  const micro = (ns - sec * NS) / 1000n;
  const d = new Date(Number(sec) * 1000);
  const two = (n: number) => String(n).padStart(2, "0");
  const parts = utc
    ? [
        d.getUTCFullYear(),
        d.getUTCMonth() + 1,
        d.getUTCDate(),
        d.getUTCHours(),
        d.getUTCMinutes(),
        d.getUTCSeconds(),
      ]
    : [
        d.getFullYear(),
        d.getMonth() + 1,
        d.getDate(),
        d.getHours(),
        d.getMinutes(),
        d.getSeconds(),
      ];
  const [y, mo, day, h, mi, se] = parts;
  return `${String(y).padStart(4, "0")}-${two(mo)}-${two(day)} ${two(h)}:${two(mi)}:${two(se)}.${micro.toString().padStart(6, "0")}`;
}

function readInterface(
  b: Buffer,
  u16: (b: Buffer, o: number) => number,
  u32: (b: Buffer, o: number) => number,
  le: boolean,
): Interface {
  const iface: Interface = {
    linkType: u16(b, 0),
    units: 1_000_000n,
    offset: 0n,
    snapLen: u32(b, 4),
  };
  let o = 8;
  while (o + 4 <= b.length) {
    const code = u16(b, o);
    const len = u16(b, o + 2);
    if (code === 0) {
      break;
    }
    if (code === 9 && len >= 1) {
      const r = b[o + 4];
      iface.units = r & 0x80 ? 1n << BigInt(r & 0x7f) : 10n ** BigInt(r);
    } else if (code === 14 && len >= 8) {
      iface.offset = le ? b.readBigInt64LE(o + 4) : b.readBigInt64BE(o + 4);
    }
    o += 4 + Math.ceil(len / 4) * 4;
  }
  return iface;
}

// -- dissection --------------------------------------------------------------------------

interface Ids {
  next: number;
}

/** What `Layer.add` returns without a tree. */
const NO_NODE: TreeNode = Object.freeze({ id: 0, src: 0, label: "" });

function node(ids: Ids, n: Omit<TreeNode, "id" | "src">): TreeNode {
  return { id: ids.next++, src: 0, ...n };
}

interface Dissected {
  src: string;
  dst: string;
  protocol: string;
  info: string;
  tree: TreeNode[];
  nextId: number;
}

/** Field adder of one protocol layer: `add(label, name, pos, size, show?)`. */
class Layer {
  readonly node: TreeNode;
  constructor(
    private readonly ctx: Ctx,
    label: string,
    name: string,
    pos: number,
    size: number,
    /** Where the protocol's data ends, for filters (`tcp contains …` covers the payload too). */
    extent = ctx.d.length,
  ) {
    this.node = ctx.withTree
      ? node(ctx.ids, { label, name, pos, size: Math.max(0, size), proto: true, children: [] })
      : { id: 0, src: 0, label };
    if (ctx.withTree) {
      ctx.tree.push(this.node);
    }
    put(ctx, name, ctx.d.subarray(pos, Math.max(pos, extent)));
  }
  add(label: string, name: string | undefined, pos: number, size: number, show?: string): TreeNode {
    if (
      name &&
      show !== undefined &&
      this.ctx.fields &&
      (!this.ctx.wanted || this.ctx.wanted.has(name))
    ) {
      put(this.ctx, name, fieldValue(this.ctx.d, name, show, pos, size));
    }
    if (!this.ctx.withTree) {
      return NO_NODE; // (the list's columns and filters need no tree)
    }
    const child = node(this.ctx.ids, { label, pos, size });
    if (name) {
      child.name = name;
    }
    if (show !== undefined) {
      child.show = show;
    }
    this.node.children!.push(child);
    return child;
  }
  set label(text: string) {
    this.node.label = text;
  }
}

interface Ctx {
  d: Buffer;
  withTree: boolean;
  /** Each field's values, for display filters (only when asked for). */
  fields?: Map<string, FieldValue[]>;
  /** Only these fields' values (all when absent). */
  wanted?: ReadonlySet<string>;
  ids: Ids;
  tree: TreeNode[];
  src: string;
  dst: string;
  protocol: string;
  info: string;
}

const hex2 = (n: number) => n.toString(16).padStart(2, "0");
const hexN = (n: number, w: number) => `0x${n.toString(16).padStart(w, "0")}`;
const mac = (b: Buffer, o: number) => {
  const h = b.toString("hex", o, o + 6);
  return `${h.slice(0, 2)}:${h.slice(2, 4)}:${h.slice(4, 6)}:${h.slice(6, 8)}:${h.slice(8, 10)}:${h.slice(10, 12)}`;
};
const ip4 = (b: Buffer, o: number) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

function ip6(b: Buffer, o: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push(b.readUInt16BE(o + i * 2));
  }
  // The longest run of zero groups (at least two) becomes "::".
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const text = groups.map((g) => g.toString(16));
  if (best < 0) {
    return text.join(":");
  }
  return `${text.slice(0, best).join(":")}::${text.slice(best + bestLen).join(":")}`;
}

/** Record a value of field `name` (when the packet's fields are being collected). */
function put(ctx: Ctx, name: string, value: FieldValue): void {
  if (!ctx.fields || (ctx.wanted && !ctx.wanted.has(name))) {
    return;
  }
  const list = ctx.fields.get(name);
  if (list) {
    list.push(value);
  } else {
    ctx.fields.set(name, [value]);
  }
}

/** A tree field's value for filters: numbers as numbers, byte fields as bytes, else the text. */
function fieldValue(d: Buffer, name: string, show: string, pos: number, size: number): FieldValue {
  switch (basicFieldType(name)) {
    case "FT_BYTES":
      return d.subarray(pos, pos + Math.max(0, size));
    case "FT_BOOLEAN":
    case "FT_UINT8":
    case "FT_UINT16":
    case "FT_UINT24":
    case "FT_UINT32":
      return Number(show);
    default:
      return show;
  }
}

/**
 * Decode one packet's headers: the list's columns and (with `withTree`) the
 * detail tree; with `fields`, each field's values go there too (filters).
 */
export function dissect(
  d: Buffer,
  linkType: number,
  withTree: boolean,
  fields?: Map<string, FieldValue[]>,
  wanted?: ReadonlySet<string>,
): Dissected {
  const ctx: Ctx = {
    d,
    withTree,
    fields,
    wanted,
    ids: { next: 1000 },
    tree: [],
    src: "",
    dst: "",
    protocol: "",
    info: "",
  };
  try {
    link(ctx, linkType);
  } catch (err) {
    if (!(err instanceof RangeError)) {
      throw err;
    }
    // A header cut short: what was decoded stays, marked as such.
    malformed(ctx, "the packet ends inside a header");
  }
  if (!ctx.protocol) {
    ctx.protocol = LINK_TYPES[linkType] ? "Data" : `Link type ${linkType}`;
  }
  if (!ctx.info) {
    ctx.info = `${d.length} bytes`;
  }
  return {
    src: ctx.src,
    dst: ctx.dst,
    protocol: ctx.protocol,
    info: ctx.info,
    tree: ctx.tree,
    nextId: ctx.ids.next,
  };
}

function malformed(ctx: Ctx, why: string): void {
  ctx.info = ctx.info ? `${ctx.info} [Malformed: ${why}]` : `[Malformed: ${why}]`;
  put(ctx, "_ws.malformed", Buffer.alloc(0));
  if (ctx.withTree) {
    ctx.tree.push(node(ctx.ids, { label: `[Malformed Packet: ${why}]`, name: "_ws.malformed" }));
  }
}

function link(ctx: Ctx, linkType: number): void {
  const d = ctx.d;
  switch (linkType) {
    case 1:
      return ethernet(ctx, 0);
    case 0:
    case 108: {
      const family = linkType === 0 ? d.readUInt32LE(0) : d.readUInt32BE(0);
      const l = new Layer(ctx, `Null/Loopback, Family: ${family}`, "null", 0, 4);
      l.add(`Family: ${family}`, "null.family", 0, 4, String(family));
      return rawIp(ctx, 4);
    }
    case 12:
    case 14:
    case 101:
    case 228:
    case 229:
      return rawIp(ctx, 0);
    case 105:
      return wlan(ctx, 0);
    case 127: {
      const len = d.readUInt16LE(2);
      const l = new Layer(ctx, `Radiotap Header v${d[0]}, Length ${len}`, "radiotap", 0, len);
      l.add(`Header length: ${len}`, "radiotap.length", 2, 2, String(len));
      return wlan(ctx, len);
    }
    case 113: {
      const l = new Layer(ctx, "Linux cooked capture v1", "sll", 0, 16);
      l.add(`Packet type: ${d.readUInt16BE(0)}`, "sll.pkttype", 0, 2, String(d.readUInt16BE(0)));
      const alen = d.readUInt16BE(4);
      if (alen === 6) {
        ctx.src = mac(d, 6);
        l.add(`Source: ${ctx.src}`, "sll.src.eth", 6, 6, ctx.src);
      }
      const type = d.readUInt16BE(14);
      l.add(`Protocol: ${hexN(type, 4)}`, "sll.etype", 14, 2, hexN(type, 4));
      return etherType(ctx, type, 16);
    }
    case 276: {
      const l = new Layer(ctx, "Linux cooked capture v2", "sll", 0, 20);
      const type = d.readUInt16BE(0);
      l.add(`Protocol: ${hexN(type, 4)}`, "sll.etype", 0, 2, hexN(type, 4));
      l.add(
        `Interface index: ${d.readUInt32BE(4)}`,
        "sll.ifindex",
        4,
        4,
        String(d.readUInt32BE(4)),
      );
      if (d[11] === 6) {
        ctx.src = mac(d, 12);
        l.add(`Source: ${ctx.src}`, "sll.src.eth", 12, 6, ctx.src);
      }
      return etherType(ctx, type, 20);
    }
    default:
      return;
  }
}

const WLAN_TYPES = ["Management", "Control", "Data", "Extension"];

/** An 802.11 frame's header: addresses (transmitter → receiver) and, for data, LLC/SNAP. */
function wlan(ctx: Ctx, o: number): void {
  const d = ctx.d;
  const fc = d.readUInt16LE(o);
  const type = (fc >> 2) & 3;
  const subtype = (fc >> 4) & 15;
  const ra = mac(d, o + 4);
  const l = new Layer(ctx, `IEEE 802.11 ${WLAN_TYPES[type]} frame`, "wlan", o, 24);
  l.add(`Frame Control Field: ${hexN(fc, 4)}`, "wlan.fc", o, 2, hexN(fc, 4));
  l.add(`Receiver address: ${ra}`, "wlan.ra", o + 4, 6, ra);
  put(ctx, "wlan.addr", ra);
  ctx.protocol = "802.11";
  ctx.dst = ra;
  ctx.info = `${WLAN_TYPES[type]} frame, subtype ${subtype}`;
  if (type === 1) {
    return; // (control frames: no transmitter address in most)
  }
  const ta = mac(d, o + 10);
  l.add(`Transmitter address: ${ta}`, "wlan.ta", o + 10, 6, ta);
  put(ctx, "wlan.addr", ta);
  ctx.src = ta;
  if (type !== 2) {
    return;
  }
  // Source and destination as Wireshark shows them, by the To/From DS bits.
  const a3 = mac(d, o + 16);
  const ds = (fc >> 8) & 3;
  if (ds === 1) {
    ctx.dst = a3;
  } else if (ds === 2) {
    ctx.src = a3;
  } else if (ds === 3) {
    ctx.dst = a3;
    ctx.src = mac(d, o + 24);
  }
  l.add(`Address 3: ${a3}`, "wlan.addr", o + 16, 6, a3);
  const protectedFrame = (fc & 0x4000) !== 0;
  const qos = subtype & 8 ? 2 : 0;
  const body = o + 24 + qos + ((fc & 0x0300) === 0x0300 ? 6 : 0);
  if (protectedFrame) {
    ctx.info = `Data frame, protected (${d.length - body} bytes)`;
    return;
  }
  // LLC/SNAP: AA AA 03 + OUI + EtherType.
  if (d[body] === 0xaa && d[body + 1] === 0xaa && d[body + 2] === 3) {
    const etype = d.readUInt16BE(body + 6);
    const llc = new Layer(ctx, "Logical-Link Control", "llc", body, 8);
    llc.add(
      `Type: ${ETHER_TYPES[etype] ?? "Unknown"} (${hexN(etype, 4)})`,
      "llc.type",
      body + 6,
      2,
      hexN(etype, 4),
    );
    etherType(ctx, etype, body + 8);
  }
}

function ethernet(ctx: Ctx, o: number): void {
  const d = ctx.d;
  const dst = mac(d, o);
  const src = mac(d, o + 6);
  const type = d.readUInt16BE(o + 12);
  const l = new Layer(ctx, `Ethernet II, Src: ${src}, Dst: ${dst}`, "eth", o, 14);
  l.add(`Destination: ${dst}`, "eth.dst", o, 6, dst);
  l.add(`Source: ${src}`, "eth.src", o + 6, 6, src);
  l.add(
    `Type: ${ETHER_TYPES[type] ?? "Unknown"} (${hexN(type, 4)})`,
    "eth.type",
    o + 12,
    2,
    hexN(type, 4),
  );
  put(ctx, "eth.addr", dst);
  put(ctx, "eth.addr", src);
  ctx.src = src;
  ctx.dst = dst;
  if (type <= 1500) {
    ctx.protocol = "LLC";
    ctx.info = `IEEE 802.3 frame, ${type} bytes`;
    return;
  }
  etherType(ctx, type, o + 14);
}

const ETHER_TYPES: Record<number, string> = {
  0x0800: "IPv4",
  0x0806: "ARP",
  0x8100: "802.1Q Virtual LAN",
  0x86dd: "IPv6",
  0x88cc: "LLDP",
  0x8847: "MPLS",
  0x88a8: "802.1ad",
};

function etherType(ctx: Ctx, type: number, o: number): void {
  const d = ctx.d;
  switch (type) {
    case 0x0800:
      return ipv4(ctx, o);
    case 0x86dd:
      return ipv6(ctx, o);
    case 0x0806:
      return arp(ctx, o);
    case 0x8100:
    case 0x88a8: {
      const tci = d.readUInt16BE(o);
      const inner = d.readUInt16BE(o + 2);
      const l = new Layer(
        ctx,
        `802.1Q Virtual LAN, PRI: ${tci >> 13}, ID: ${tci & 0xfff}`,
        "vlan",
        o,
        4,
      );
      l.add(`ID: ${tci & 0xfff}`, "vlan.id", o, 2, String(tci & 0xfff));
      l.add(
        `Type: ${ETHER_TYPES[inner] ?? "Unknown"} (${hexN(inner, 4)})`,
        "vlan.etype",
        o + 2,
        2,
        hexN(inner, 4),
      );
      return etherType(ctx, inner, o + 4);
    }
    default:
      ctx.protocol = ETHER_TYPES[type] ?? `Ethertype ${hexN(type, 4)}`;
      ctx.info = `Ethertype ${hexN(type, 4)}`;
  }
}

function rawIp(ctx: Ctx, o: number): void {
  const version = ctx.d[o] >> 4;
  if (version === 4) {
    ipv4(ctx, o);
  } else if (version === 6) {
    ipv6(ctx, o);
  } else {
    ctx.protocol = "Data";
  }
}

function arp(ctx: Ctx, o: number): void {
  const d = ctx.d;
  const op = d.readUInt16BE(o + 6);
  const l = new Layer(
    ctx,
    `Address Resolution Protocol (${op === 1 ? "request" : op === 2 ? "reply" : op})`,
    "arp",
    o,
    28,
  );
  l.add(
    `Opcode: ${op === 1 ? "request" : op === 2 ? "reply" : "unknown"} (${op})`,
    "arp.opcode",
    o + 6,
    2,
    String(op),
  );
  const smac = mac(d, o + 8);
  const sip = ip4(d, o + 14);
  const tmac = mac(d, o + 18);
  const tip = ip4(d, o + 24);
  l.add(`Sender MAC address: ${smac}`, "arp.src.hw_mac", o + 8, 6, smac);
  l.add(`Sender IP address: ${sip}`, "arp.src.proto_ipv4", o + 14, 4, sip);
  l.add(`Target MAC address: ${tmac}`, "arp.dst.hw_mac", o + 18, 6, tmac);
  l.add(`Target IP address: ${tip}`, "arp.dst.proto_ipv4", o + 24, 4, tip);
  ctx.protocol = "ARP";
  ctx.info =
    op === 1 ? `Who has ${tip}? Tell ${sip}` : op === 2 ? `${sip} is at ${smac}` : `Opcode ${op}`;
}

const IP_PROTOCOLS: Record<number, string> = {
  1: "ICMP",
  2: "IGMP",
  6: "TCP",
  17: "UDP",
  41: "IPv6",
  47: "GRE",
  50: "ESP",
  51: "AH",
  58: "ICMPv6",
  89: "OSPF",
  132: "SCTP",
};

function ipv4(ctx: Ctx, o: number): void {
  const d = ctx.d;
  const ihl = (d[o] & 15) * 4;
  const total = d.readUInt16BE(o + 2);
  const id = d.readUInt16BE(o + 4);
  const frag = d.readUInt16BE(o + 6);
  const ttl = d[o + 8];
  const proto = d[o + 9];
  const src = ip4(d, o + 12);
  const dst = ip4(d, o + 16);
  const l = new Layer(
    ctx,
    `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`,
    "ip",
    o,
    ihl,
    Math.min(d.length, o + Math.max(total, ihl)),
  );
  l.add(`0100 .... = Version: 4`, "ip.version", o, 1, "4");
  l.add(
    `.... ${((d[o] & 15) >>> 0).toString(2).padStart(4, "0")} = Header Length: ${ihl} bytes (${ihl / 4})`,
    "ip.hdr_len",
    o,
    1,
    String(ihl),
  );
  l.add(`Total Length: ${total}`, "ip.len", o + 2, 2, String(total));
  l.add(`Identification: ${hexN(id, 4)} (${id})`, "ip.id", o + 4, 2, hexN(id, 4));
  l.add(
    `Flags: ${hexN(frag >> 13, 1)}${frag & 0x4000 ? ", Don't fragment" : ""}${frag & 0x2000 ? ", More fragments" : ""}`,
    "ip.flags",
    o + 6,
    1,
    hexN(frag >> 13, 2),
  );
  put(ctx, "ip.flags.df", (frag >> 14) & 1);
  put(ctx, "ip.flags.mf", (frag >> 13) & 1);
  l.add(
    `Fragment Offset: ${(frag & 0x1fff) * 8}`,
    "ip.frag_offset",
    o + 6,
    2,
    String((frag & 0x1fff) * 8),
  );
  l.add(`Time to Live: ${ttl}`, "ip.ttl", o + 8, 1, String(ttl));
  l.add(
    `Protocol: ${IP_PROTOCOLS[proto] ?? "Unknown"} (${proto})`,
    "ip.proto",
    o + 9,
    1,
    String(proto),
  );
  const checksum = hexN(d.readUInt16BE(o + 10), 4);
  l.add(`Header Checksum: ${checksum}`, "ip.checksum", o + 10, 2, checksum);
  l.add(`Source Address: ${src}`, "ip.src", o + 12, 4, src);
  l.add(`Destination Address: ${dst}`, "ip.dst", o + 16, 4, dst);
  put(ctx, "ip.addr", src);
  put(ctx, "ip.addr", dst);
  ctx.src = src;
  ctx.dst = dst;
  if (ihl < 20) {
    malformed(ctx, `IPv4 header length ${ihl} is under 20 bytes`);
    return;
  }
  const end = Math.min(d.length, o + Math.max(total, ihl));
  if ((frag & 0x1fff) !== 0) {
    ctx.protocol = "IPv4";
    ctx.info = `Fragmented IP protocol (proto=${IP_PROTOCOLS[proto] ?? proto} ${proto}, off=${(frag & 0x1fff) * 8}, ID=${hex4(id)})`;
    return;
  }
  transport(ctx, proto, o + ihl, end, ttl);
}

const hex4 = (n: number) => n.toString(16).padStart(4, "0");

function ipv6(ctx: Ctx, o: number): void {
  const d = ctx.d;
  const plen = d.readUInt16BE(o + 4);
  let next = d[o + 6];
  const hlim = d[o + 7];
  const src = ip6(d, o + 8);
  const dst = ip6(d, o + 24);
  const l = new Layer(
    ctx,
    `Internet Protocol Version 6, Src: ${src}, Dst: ${dst}`,
    "ipv6",
    o,
    40,
    Math.min(d.length, o + 40 + plen),
  );
  l.add(`0110 .... = Version: 6`, "ipv6.version", o, 1, "6");
  l.add(`Payload Length: ${plen}`, "ipv6.plen", o + 4, 2, String(plen));
  l.add(
    `Next Header: ${IP_PROTOCOLS[next] ?? "Unknown"} (${next})`,
    "ipv6.nxt",
    o + 6,
    1,
    String(next),
  );
  l.add(`Hop Limit: ${hlim}`, "ipv6.hlim", o + 7, 1, String(hlim));
  l.add(`Source Address: ${src}`, "ipv6.src", o + 8, 16, src);
  l.add(`Destination Address: ${dst}`, "ipv6.dst", o + 24, 16, dst);
  put(ctx, "ipv6.addr", src);
  put(ctx, "ipv6.addr", dst);
  ctx.src = src;
  ctx.dst = dst;
  const end = Math.min(d.length, o + 40 + plen);
  let p = o + 40;
  // Extension headers: hop-by-hop, routing, destination options; a fragment stops here.
  for (let n = 0; n < 8 && [0, 43, 60, 44].includes(next); n++) {
    if (next === 44) {
      const off = d.readUInt16BE(p + 2) >> 3;
      l.add(`Fragment Header, offset ${off * 8}`, "ipv6.fraghdr", p, 8);
      if (off !== 0) {
        ctx.protocol = "IPv6";
        ctx.info = `IPv6 fragment (off=${off * 8}, nxt=${d[p]})`;
        return;
      }
      next = d[p];
      p += 8;
      continue;
    }
    const len = (d[p + 1] + 1) * 8;
    l.add(
      `${next === 0 ? "Hop-by-Hop Options" : next === 43 ? "Routing Header" : "Destination Options"} (${len} bytes)`,
      undefined,
      p,
      len,
    );
    next = d[p];
    p += len;
  }
  transport(ctx, next, p, end, hlim);
}

function transport(ctx: Ctx, proto: number, o: number, end: number, ttl: number): void {
  switch (proto) {
    case 6:
      return tcp(ctx, o, end);
    case 17:
      return udp(ctx, o, end);
    case 1:
      return icmp(ctx, o, end, ttl);
    case 58:
      return icmpv6(ctx, o, end);
    case 4:
      return ipv4(ctx, o);
    case 41:
      return ipv6(ctx, o);
    default:
      ctx.protocol = IP_PROTOCOLS[proto] ?? `IP protocol ${proto}`;
      ctx.info = `${ctx.protocol}, ${Math.max(0, end - o)} bytes`;
  }
}

const TCP_FLAG_FIELDS: [number, string][] = [
  [0x01, "tcp.flags.fin"],
  [0x02, "tcp.flags.syn"],
  [0x04, "tcp.flags.reset"],
  [0x08, "tcp.flags.push"],
  [0x10, "tcp.flags.ack"],
  [0x20, "tcp.flags.urg"],
];
const TCP_FLAGS: [number, string][] = [
  [0x02, "SYN"],
  [0x01, "FIN"],
  [0x04, "RST"],
  [0x08, "PSH"],
  [0x10, "ACK"],
  [0x20, "URG"],
  [0x40, "ECE"],
  [0x80, "CWR"],
];

function tcp(ctx: Ctx, o: number, end: number): void {
  const d = ctx.d;
  const sp = d.readUInt16BE(o);
  const dp = d.readUInt16BE(o + 2);
  const seq = d.readUInt32BE(o + 4);
  const ack = d.readUInt32BE(o + 8);
  const doff = (d[o + 12] >> 4) * 4;
  const flags = ((d[o + 12] & 1) << 8) | d[o + 13];
  const win = d.readUInt16BE(o + 14);
  const names = TCP_FLAGS.filter(([bit]) => flags & bit).map(([, n]) => n);
  // Wireshark's order: SYN, FIN, RST, PSH, ACK…, as in "[SYN, ACK]".
  const l = new Layer(
    ctx,
    `Transmission Control Protocol, Src Port: ${sp}, Dst Port: ${dp}, Seq: ${seq}${flags & 0x10 ? `, Ack: ${ack}` : ""}`,
    "tcp",
    o,
    doff,
    end,
  );
  l.add(`Source Port: ${sp}`, "tcp.srcport", o, 2, String(sp));
  l.add(`Destination Port: ${dp}`, "tcp.dstport", o + 2, 2, String(dp));
  l.add(`Sequence Number (raw): ${seq}`, "tcp.seq_raw", o + 4, 4, String(seq));
  l.add(`Acknowledgment number (raw): ${ack}`, "tcp.ack_raw", o + 8, 4, String(ack));
  l.add(
    `${((d[o + 12] >> 4) >>> 0).toString(2).padStart(4, "0")} .... = Header Length: ${doff} bytes (${doff / 4})`,
    "tcp.hdr_len",
    o + 12,
    1,
    String(doff),
  );
  l.add(
    `Flags: ${hexN(flags, 3)} (${names.join(", ") || "none"})`,
    "tcp.flags",
    o + 12,
    2,
    hexN(flags, 4),
  );
  put(ctx, "tcp.port", sp);
  put(ctx, "tcp.port", dp);
  for (const [bit, name] of TCP_FLAG_FIELDS) {
    put(ctx, name, flags & bit ? 1 : 0);
  }
  l.add(`Window: ${win}`, "tcp.window_size_value", o + 14, 2, String(win));
  const checksum = hexN(d.readUInt16BE(o + 16), 4);
  l.add(`Checksum: ${checksum}`, "tcp.checksum", o + 16, 2, checksum);
  const urgent = d.readUInt16BE(o + 18);
  l.add(`Urgent Pointer: ${urgent}`, "tcp.urgent_pointer", o + 18, 2, String(urgent));
  if (doff < 20 || o + doff > end) {
    ctx.protocol = "TCP";
    malformed(ctx, `TCP header length ${doff} is wrong`);
    return;
  }
  if (doff > 20) {
    l.add(`Options: (${doff - 20} bytes)`, "tcp.options", o + 20, doff - 20, "");
  }
  const len = end - o - doff;
  put(ctx, "tcp.len", len);
  l.label = `${l.node.label}, Len: ${len}`;
  ctx.protocol = "TCP";
  ctx.info = `${sp} → ${dp} [${names.join(", ")}] Seq=${seq}${flags & 0x10 ? ` Ack=${ack}` : ""} Win=${win} Len=${len}`;
  if (len > 0) {
    application(ctx, o + doff, end, sp, dp, "tcp");
  }
}

function udp(ctx: Ctx, o: number, end: number): void {
  const d = ctx.d;
  const sp = d.readUInt16BE(o);
  const dp = d.readUInt16BE(o + 2);
  const len = d.readUInt16BE(o + 4);
  const l = new Layer(
    ctx,
    `User Datagram Protocol, Src Port: ${sp}, Dst Port: ${dp}`,
    "udp",
    o,
    8,
    Math.min(end, o + Math.max(len, 8)),
  );
  l.add(`Source Port: ${sp}`, "udp.srcport", o, 2, String(sp));
  l.add(`Destination Port: ${dp}`, "udp.dstport", o + 2, 2, String(dp));
  l.add(`Length: ${len}`, "udp.length", o + 4, 2, String(len));
  const checksum = hexN(d.readUInt16BE(o + 6), 4);
  l.add(`Checksum: ${checksum}`, "udp.checksum", o + 6, 2, checksum);
  put(ctx, "udp.port", sp);
  put(ctx, "udp.port", dp);
  ctx.protocol = "UDP";
  const payloadEnd = Math.min(end, o + Math.max(len, 8));
  ctx.info = `${sp} → ${dp} Len=${Math.max(0, payloadEnd - o - 8)}`;
  if (payloadEnd > o + 8) {
    application(ctx, o + 8, payloadEnd, sp, dp, "udp");
  }
}

const ICMP_TYPES: Record<number, string> = {
  0: "Echo (ping) reply",
  3: "Destination unreachable",
  5: "Redirect",
  8: "Echo (ping) request",
  11: "Time-to-live exceeded",
};

function icmp(ctx: Ctx, o: number, end: number, ttl: number): void {
  const d = ctx.d;
  const type = d[o];
  const code = d[o + 1];
  const l = new Layer(ctx, "Internet Control Message Protocol", "icmp", o, end - o);
  l.add(`Type: ${type} (${ICMP_TYPES[type] ?? "Unknown"})`, "icmp.type", o, 1, String(type));
  l.add(`Code: ${code}`, "icmp.code", o + 1, 1, String(code));
  const checksum = hexN(d.readUInt16BE(o + 2), 4);
  l.add(`Checksum: ${checksum}`, "icmp.checksum", o + 2, 2, checksum);
  ctx.protocol = "ICMP";
  ctx.info = ICMP_TYPES[type] ?? `Type ${type}, code ${code}`;
  if ((type === 0 || type === 8) && end - o >= 8) {
    const id = d.readUInt16BE(o + 4);
    const seq = d.readUInt16BE(o + 6);
    l.add(`Identifier (BE): ${id} (${hexN(id, 4)})`, "icmp.ident", o + 4, 2, String(id));
    l.add(`Sequence Number (BE): ${seq} (${hexN(seq, 4)})`, "icmp.seq", o + 6, 2, String(seq));
    ctx.info = `${ICMP_TYPES[type]}  id=${hexN(id, 4)}, seq=${seq}/${d.readUInt16LE(o + 6)}, ttl=${ttl}`;
  }
}

const ICMPV6_TYPES: Record<number, string> = {
  1: "Destination Unreachable",
  3: "Time Exceeded",
  128: "Echo (ping) request",
  129: "Echo (ping) reply",
  133: "Router Solicitation",
  134: "Router Advertisement",
  135: "Neighbor Solicitation",
  136: "Neighbor Advertisement",
};

function icmpv6(ctx: Ctx, o: number, end: number): void {
  const d = ctx.d;
  const type = d[o];
  const l = new Layer(ctx, "Internet Control Message Protocol v6", "icmpv6", o, end - o);
  l.add(`Type: ${ICMPV6_TYPES[type] ?? "Unknown"} (${type})`, "icmpv6.type", o, 1, String(type));
  l.add(`Code: ${d[o + 1]}`, "icmpv6.code", o + 1, 1, String(d[o + 1]));
  ctx.protocol = "ICMPv6";
  ctx.info = ICMPV6_TYPES[type] ?? `Type ${type}`;
  if ((type === 135 || type === 136) && end - o >= 24) {
    const target = ip6(d, o + 8);
    l.add(`Target Address: ${target}`, "icmpv6.nd.ns.target_address", o + 8, 16, target);
    ctx.info += ` for ${target}`;
  }
}

const TLS_PORTS = new Set([443, 465, 636, 853, 993, 995, 8443]);
const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "PATCH",
  "CONNECT",
  "TRACE",
];
const TLS_CONTENT: Record<number, string> = {
  20: "Change Cipher Spec",
  21: "Alert",
  22: "Handshake",
  23: "Application Data",
};
const TLS_HANDSHAKE: Record<number, string> = {
  1: "Client Hello",
  2: "Server Hello",
  4: "New Session Ticket",
  11: "Certificate",
  12: "Server Key Exchange",
  14: "Server Hello Done",
  16: "Client Key Exchange",
};

function application(
  ctx: Ctx,
  o: number,
  end: number,
  sp: number,
  dp: number,
  proto: "tcp" | "udp",
): void {
  const d = ctx.d;
  const port = (p: number) => sp === p || dp === p;
  if (port(53) || port(5353)) {
    const skip = proto === "tcp" ? 2 : 0;
    if (end - o - skip >= 12) {
      return dns(ctx, o + skip, end, port(5353) ? "MDNS" : "DNS");
    }
  }
  // (A look at the first bytes before reading the line: most payloads aren't HTTP.)
  const peek = d.toString("latin1", o, Math.min(end, o + 8));
  const http =
    peek.startsWith("HTTP/1.") || HTTP_METHODS.some((m) => peek.startsWith(`${m} `.slice(0, 8)));
  const head = http ? d.toString("latin1", o, Math.min(end, o + 2048)) : "";
  const lineEnd = head.indexOf("\r\n");
  const first = lineEnd > 0 ? head.slice(0, lineEnd) : "";
  if (first.startsWith("HTTP/1.") || HTTP_METHODS.some((m) => first.startsWith(`${m} `))) {
    const l = new Layer(ctx, "Hypertext Transfer Protocol", "http", o, end - o);
    l.add(first, undefined, o, lineEnd + 2);
    httpFields(ctx, first);
    ctx.protocol = "HTTP";
    ctx.info = first;
    return;
  }
  if (end - o >= 5 && TLS_CONTENT[d[o]] && d[o + 1] === 3 && d[o + 2] <= 4) {
    const types: string[] = [];
    const l = new Layer(ctx, "Transport Layer Security", "tls", o, end - o);
    for (let p = o; p + 5 <= end && TLS_CONTENT[d[p]] && types.length < 8;) {
      const len = d.readUInt16BE(p + 3);
      let what = TLS_CONTENT[d[p]];
      if (d[p] === 22 && p + 6 <= end) {
        what = TLS_HANDSHAKE[d[p + 5]] ?? "Handshake";
      }
      types.push(what);
      put(ctx, "tls.record.content_type", d[p]);
      put(ctx, "tls.record.version", d.readUInt16BE(p + 1));
      put(ctx, "tls.record.length", len);
      if (d[p] === 22 && p + 6 <= end) {
        put(ctx, "tls.handshake.type", d[p + 5]);
      }
      l.add(
        `TLS Record Layer: ${TLS_CONTENT[d[p]]}, Length: ${len}`,
        "tls.record",
        p,
        Math.min(5 + len, end - p),
        "",
      );
      p += 5 + len;
    }
    ctx.protocol = "TLS";
    ctx.info = [...new Set(types)].join(", ");
    return;
  }
  const l = new Layer(ctx, `Data (${end - o} bytes)`, "data", o, end - o);
  l.add(
    `Data: ${d.toString("hex", o, Math.min(end, o + 32))}${end - o > 32 ? "…" : ""}`,
    "data.data",
    o,
    end - o,
    "",
  );
  put(ctx, "data.len", end - o);
  if (TLS_PORTS.has(sp) || TLS_PORTS.has(dp)) {
    ctx.protocol = "TLS";
    ctx.info = `Continuation Data, ${end - o} bytes`;
  }
}

const DNS_TYPES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS",
  255: "ANY",
};
const DNS_RCODES: Record<number, string> = {
  1: "Format error",
  2: "Server failure",
  3: "No such name",
  5: "Refused",
};

/** A DNS name at `p` (with compression pointers, at most 32 jumps), and where it ends. */
function dnsName(d: Buffer, base: number, p: number, end: number): { name: string; next: number } {
  const labels: string[] = [];
  let next = -1;
  for (let jumps = 0; jumps < 32 && p < end;) {
    const len = d[p];
    if (len === 0) {
      p++;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (next < 0) {
        next = p + 2;
      }
      p = base + (((len & 0x3f) << 8) | d[p + 1]);
      jumps++;
      continue;
    }
    labels.push(d.toString("latin1", p + 1, Math.min(end, p + 1 + len)));
    p += 1 + len;
  }
  return { name: labels.join(".") || "<Root>", next: next < 0 ? p : next };
}

/** HTTP's first line as tshark's fields: a request's method, URI and version, or a response's. */
function httpFields(ctx: Ctx, first: string): void {
  if (!ctx.fields) {
    return;
  }
  const response = /^(HTTP\/\d\.\d) (\d{3})(?: (.*))?$/.exec(first);
  if (response) {
    put(ctx, "http.response", "");
    put(ctx, "http.response.version", response[1]);
    put(ctx, "http.response.code", Number(response[2]));
    put(ctx, "http.response.phrase", response[3] ?? "");
    return;
  }
  const [method, uri, version] = first.split(" ");
  put(ctx, "http.request", "");
  put(ctx, "http.request.method", method);
  if (uri !== undefined) {
    put(ctx, "http.request.uri", uri);
  }
  if (version !== undefined) {
    put(ctx, "http.request.version", version);
  }
}

function dns(ctx: Ctx, o: number, end: number, label: "DNS" | "MDNS"): void {
  const d = ctx.d;
  const id = d.readUInt16BE(o);
  const flags = d.readUInt16BE(o + 2);
  const qd = d.readUInt16BE(o + 4);
  const an = d.readUInt16BE(o + 6);
  const response = (flags & 0x8000) !== 0;
  const rcode = flags & 15;
  const l = new Layer(
    ctx,
    label === "DNS" ? "Domain Name System" : "Multicast Domain Name System",
    label === "DNS" ? "dns" : "mdns",
    o,
    end - o,
  );
  l.add(`Transaction ID: ${hexN(id, 4)}`, "dns.id", o, 2, hexN(id, 4));
  put(ctx, "dns.flags.response", response ? 1 : 0);
  put(ctx, "dns.flags.rcode", rcode);
  l.add(
    `Flags: ${hexN(flags, 4)} ${response ? "Standard query response" : "Standard query"}${rcode ? `, ${DNS_RCODES[rcode] ?? `rcode ${rcode}`}` : ""}`,
    "dns.flags",
    o + 2,
    2,
    hexN(flags, 4),
  );
  l.add(`Questions: ${qd}`, "dns.count.queries", o + 4, 2, String(qd));
  l.add(`Answer RRs: ${an}`, "dns.count.answers", o + 6, 2, String(an));
  const words: string[] = [];
  let p = o + 12;
  for (let i = 0; i < qd && p < end && i < 16; i++) {
    const q = dnsName(d, o, p, end);
    const type = d.readUInt16BE(q.next);
    l.add(`${q.name}: type ${DNS_TYPES[type] ?? type}`, "dns.qry.name", p, q.next + 4 - p, q.name);
    put(ctx, "dns.qry.type", type);
    words.push(`${DNS_TYPES[type] ?? `Unknown (${type})`} ${q.name}`);
    p = q.next + 4;
  }
  if (response) {
    for (let i = 0; i < an && p + 10 < end && i < 16; i++) {
      const r = dnsName(d, o, p, end);
      const type = d.readUInt16BE(r.next);
      const len = d.readUInt16BE(r.next + 8);
      const data = r.next + 10;
      let value = "";
      if (type === 1 && len === 4) {
        value = ip4(d, data);
        put(ctx, "dns.a", value);
      } else if (type === 28 && len === 16) {
        value = ip6(d, data);
        put(ctx, "dns.aaaa", value);
      } else if (type === 5 || type === 12 || type === 2) {
        value = dnsName(d, o, data, end).name;
        if (type === 5) {
          put(ctx, "dns.cname", value);
        }
      }
      put(ctx, "dns.resp.type", type);
      const name = `${DNS_TYPES[type] ?? type}${value ? ` ${value}` : ""}`;
      l.add(`${r.name}: type ${name}`, "dns.resp.name", p, data + len - p, r.name);
      words.push(name);
      p = data + len;
    }
  }
  ctx.protocol = label;
  const kind = response ? "Standard query response" : "Standard query";
  ctx.info =
    `${kind} ${hexN(id, 4)}${rcode ? ` ${DNS_RCODES[rcode] ?? `rcode ${rcode}`}` : ""} ${words.join(" ")}`.trim();
}

// -- requests ----------------------------------------------------------------------------

/** What the viewer calls the backend's requests the basic view can't answer. */
const NEEDS: Record<string, string> = {
  neighbor_frame: "Conversation stepping",
  expert_summary: "Expert information",
  capture_info: "Capture properties",
};

/** A request the viewer cancelled (or a newer filter replaced). */
export class BasicCancelledError extends Error {
  constructor() {
    super("request cancelled");
  }
}

/** Cancellation and progress of one request. */
export interface BasicRequestContext {
  cancelled?: boolean;
  progress?: (fraction: number, phase: string) => void;
}

const MAX_VALUES = 200;
const MAX_DISTINCT = 10_000;
const MAX_HINT_FIELDS = 8;

function intParam(params: Record<string, unknown>, key: string, fallback?: number): number {
  const v = params[key] ?? fallback;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new RangeError(`${key} must be an integer`);
  }
  return v;
}

function strParam(params: Record<string, unknown>, key: string, fallback = ""): string {
  const v = params[key] ?? fallback;
  if (typeof v !== "string") {
    throw new RangeError(`${key} must be a string`);
  }
  return v;
}

function frameList(params: Record<string, unknown>, count: number): number[] {
  const frames = Array.isArray(params.frames) ? params.frames : [];
  return [...new Set(frames)].filter(
    (n): n is number => Number.isInteger(n) && n >= 1 && n <= count,
  );
}

/** A field value as tshark's `-T fields` would print it (bytes as aa:bb:cc). */
function valueText(v: FieldValue): string {
  return Buffer.isBuffer(v) ? [...v].map(hex2).join(":") : String(v);
}

/**
 * Answer one of the viewer's backend requests from `capture`. Rows come in
 * capture order (sorting needs tshark); custom columns are blank. Display
 * filters, Find Packet and the filter builder read the basic dissector's
 * fields (src/basicFilter.ts). Throws NeedsToolsError for what only tshark
 * can do, BasicFilterError for a filter it can't read, BasicCancelledError
 * when `ctx` is cancelled. Requests that read every packet return a promise.
 */
export function basicRequest(
  capture: BasicCapture,
  method: string,
  params: Record<string, unknown>,
  ctx: BasicRequestContext = {},
): unknown {
  const count = capture.count;
  const view = capture.view;
  switch (method) {
    case "list_packets": {
      const extra = Array.isArray(params.columns)
        ? params.columns.filter((c) => !BASIC_COLUMNS.some((b) => b.field === c))
        : [];
      let frames: number[];
      if (Array.isArray(params.frames)) {
        frames = frameList(params, count).slice(0, MAX_PAGE);
        if (params.inView !== false) {
          frames = frames.filter((n) => capture.indexOf(n) >= 0).sort((a, b) => a - b);
        }
      } else {
        const offset = Math.max(0, intParam(params, "offset", 0));
        const limit = Math.min(MAX_PAGE, Math.max(0, intParam(params, "limit", 200)));
        frames = capture.viewSlice(offset, limit);
      }
      const format = typeof params.timeFormat === "string" ? params.timeFormat : "relative";
      const ref = params.timeRef ?? null;
      if (
        ref !== null &&
        (!Number.isInteger(ref) || (ref as number) < 1 || (ref as number) > count)
      ) {
        throw new RangeError(`timeRef must be a frame number 1..${count}`);
      }
      const rows = frames.map((n) => {
        const cells = [...capture.row(n).cells, ...extra.map(() => "")];
        cells[1] = capture.timeText(n, format, ref as number | null, capture.previousShown(n));
        const row: { number: number; cells: string[]; marked?: boolean; ignored?: boolean } = {
          number: n,
          cells,
        };
        if (capture.marks.has(n)) {
          row.marked = true;
        }
        if (capture.ignored.has(n)) {
          row.ignored = true;
        }
        return row;
      });
      return {
        offset: params.offset ?? 0,
        rows,
        total: capture.viewCount,
        filterId: view.filterId,
        coloringId: 0,
        columns: [...BASIC_COLUMNS.map((c) => c.field), ...extra],
        rejectedColumns: [],
      };
    }
    case "packet_detail": {
      const number = intParam(params, "number");
      if (number < 1 || number > count) {
        throw new RangeError(`there is no packet ${number}`);
      }
      return capture.detail(number);
    }
    case "find_frame":
      return { index: capture.indexOf(intParam(params, "number")), filterId: view.filterId };
    case "view_frames": {
      if (Array.isArray(params.frames)) {
        return {
          frames: frameList(params, count)
            .filter((n) => capture.indexOf(n) >= 0)
            .sort((a, b) => a - b),
          filterId: view.filterId,
        };
      }
      const offset = Math.max(0, intParam(params, "offset", 0));
      const limit = Math.max(0, intParam(params, "limit"));
      return { frames: capture.viewSlice(offset, limit), filterId: view.filterId };
    }
    case "validate_filter": {
      const expr = strParam(params, "expr").trim();
      if (!expr) {
        return { valid: true };
      }
      try {
        compileBasicFilter(expr);
        return { valid: true };
      } catch (err) {
        if (err instanceof BasicFilterError) {
          return { valid: false, error: err.message, ...(err.span ? { span: err.span } : {}) };
        }
        throw err;
      }
    }
    case "set_filter":
      return capture.setFilter(strParam(params, "expr").trim(), ctx);
    case "stop_filter":
      return { stopped: false };
    case "find_packet":
      return capture.findPacket(params, ctx);
    case "mark_packets":
    case "ignore_packets": {
      const set = method === "mark_packets" ? capture.marks : capture.ignored;
      const key = method === "mark_packets" ? "mark" : "ignore";
      const frames = frameList(params, count);
      const on =
        params[key] !== undefined && params[key] !== null
          ? Boolean(params[key])
          : !frames.every((n) => set.has(n));
      for (const n of frames) {
        if (on) {
          set.add(n);
        } else {
          set.delete(n);
        }
      }
      const yes = frames.filter((n) => set.has(n));
      const no = frames.filter((n) => !set.has(n));
      return method === "mark_packets"
        ? { count: set.size, marked: yes, unmarked: no }
        : { count: set.size, ignored: yes, unignored: no };
    }
    case "unmark_all":
      capture.marks.clear();
      return { count: 0 };
    case "unignore_all":
      capture.ignored.clear();
      return { count: 0 };
    case "field_types": {
      const names = Array.isArray(params.names) ? params.names.slice(0, 2000) : [];
      const types: Record<string, { type: string; desc: string }> = {};
      for (const name of names) {
        const field = typeof name === "string" ? basicField(name) : undefined;
        if (field) {
          types[name as string] = field;
        }
      }
      return { types };
    }
    case "field_index": {
      const limit = Math.max(0, Math.min(intParam(params, "limit", 200), 100_000));
      const words = strParam(params, "words");
      if (words) {
        return { fields: findBasicFields(words, limit) };
      }
      return searchBasicFields(strParam(params, "prefix"), limit);
    }
    case "field_values":
      return capture.fieldValues(
        strParam(params, "field").trim(),
        strParam(params, "filter").trim(),
        Math.max(1, Math.min(intParam(params, "limit", MAX_VALUES), MAX_VALUES)),
        ctx,
      );
    case "filter_hints":
      return capture.filterHints(strParam(params, "expr").trim(), ctx);
    case "packet_comments":
      return { comments: {}, edited: [], error: null };
    case "view_overview":
      return {
        rows: capture.viewCount,
        colors: [],
        flags: [],
        coloringId: 0,
        filterId: view.filterId,
      };
    default:
      throw new NeedsToolsError(NEEDS[method] ?? "This");
  }
}

/** A field's type and description for `field_types` (protocols as "FT_PROTOCOL"). */
function basicField(name: string): { type: string; desc: string } | undefined {
  const proto = BASIC_PROTOCOLS.find((p) => p.name === name);
  if (proto) {
    return { type: "FT_PROTOCOL", desc: proto.desc };
  }
  const field = BASIC_FIELDS.find((x) => x.name === name);
  return field ? { type: field.type, desc: field.desc } : undefined;
}
