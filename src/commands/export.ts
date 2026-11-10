import * as path from "node:path";
import * as vscode from "vscode";
import { revealFile, revealLabel } from "./reveal";
import { RpcError } from "../backendClient";
import { readSettings } from "../config";
import { PcapEditorProvider, PcapEditorSession, describeError } from "../pcapEditor";
import { exportFileName } from "../settingsModel";
import { requireSession } from "./filter";

interface ExportResult {
  ok: boolean;
  path: string;
  size: number;
  packets?: number;
  bytes?: number;
  warnings?: string[];
}

function backendOf(session: PcapEditorSession) {
  const backend = session.backend;
  if (!backend?.running || !session.openInfo) {
    void vscode.window.showInformationMessage("Wait for the capture to finish loading.");
    return undefined;
  }
  return backend;
}

async function chooseDestination(
  session: PcapEditorSession,
  suffix: string,
  ext: string,
  filters: Record<string, string[]>,
): Promise<string | undefined> {
  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(exportFileName(session.uri.fsPath, suffix, ext)),
    filters,
    saveLabel: "Export",
  });
  if (!uri) {
    return undefined;
  }
  if (uri.scheme !== "file") {
    void vscode.window.showErrorMessage("PCAP Lens can only export to local files.");
    return undefined;
  }
  return uri.fsPath;
}

/** Run the backend's `export` with a cancellable progress notification. */
async function runExport(
  session: PcapEditorSession,
  title: string,
  params: Record<string, unknown>,
): Promise<ExportResult | undefined> {
  const backend = backendOf(session);
  if (!backend) {
    return undefined;
  }
  try {
    return await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title, cancellable: true },
      async (progress, token) => {
        let reported = 0;
        session.showExportProgress(null); // (the viewer's bar too)
        const pending = backend.send<ExportResult>("export", params, {
          timeoutMs: 0,
          onProgress: (p) => {
            if (typeof p.fraction === "number") {
              const pct = Math.round(p.fraction * 100);
              progress.report({ increment: pct - reported, message: `${pct}%` });
              reported = pct;
              session.showExportProgress(p.fraction);
            }
          },
        });
        token.onCancellationRequested(() => backend.cancel(pending.id));
        try {
          return await pending.promise;
        } finally {
          session.showExportProgress(null, true);
        }
      },
    );
  } catch (err) {
    if (!(err instanceof RpcError && err.cancelled)) {
      void vscode.window.showErrorMessage(`PCAP Lens: export failed: ${describeError(err)}`);
    }
    return undefined;
  }
}

async function reportExport(result: ExportResult, what: string, canOpen: boolean): Promise<void> {
  const name = path.basename(result.path);
  const reveal = revealLabel();
  const actions = canOpen ? ["Open", reveal] : [reveal];
  const warning = result.warnings?.length ? ` (${result.warnings[0]})` : "";
  const choice = await vscode.window.showInformationMessage(
    `Exported ${what} to ${name}${warning}`,
    ...actions,
  );
  const uri = vscode.Uri.file(result.path);
  if (choice === "Open") {
    await vscode.commands.executeCommand("vscode.openWith", uri, PcapEditorProvider.viewType);
  } else if (choice === reveal) {
    await revealFile(result.path);
  }
}

function pickCaptureFormat(title: string, format?: string, placeHolder = "File format") {
  return choose(
    [
      { id: "pcapng", label: "pcapng", description: "Wireshark's default format", ext: "pcapng" },
      { id: "pcap", label: "pcap", description: "libpcap, for older tools", ext: "pcap" },
    ],
    format,
    { title, placeHolder },
  );
}

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

/**
 * Answers to an export command's questions, so it runs without them (the
 * smoke test; other extensions): `dest` is the file to write, and then no
 * notification follows; `scope` and `format` name a choice by its id
 * ("displayed", "all", "selected", "marked"; "pcapng", "csv", "text"…).
 */
export interface ExportArgs {
  dest?: string;
  scope?: string;
  format?: string;
  /** Dissections: add each packet's hex dump. */
  bytes?: boolean;
  /** Packet bytes: which data source (0 = the frame). */
  source?: number;
}

/** Validated ExportArgs (a command may be run with anything). */
function exportArgs(args: unknown): ExportArgs {
  if (!args || typeof args !== "object") {
    return {};
  }
  const a = args as Record<string, unknown>;
  const text = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  return {
    dest: text(a.dest),
    scope: text(a.scope),
    format: text(a.format),
    bytes: typeof a.bytes === "boolean" ? a.bytes : undefined,
    source: typeof a.source === "number" && Number.isInteger(a.source) ? a.source : undefined,
  };
}

/** The item `id` names when given (an unknown id is an error), else the user's pick. */
async function choose<T extends vscode.QuickPickItem & { id: string }>(
  items: T[],
  id: string | undefined,
  options: vscode.QuickPickOptions,
): Promise<T | undefined> {
  if (id === undefined) {
    return vscode.window.showQuickPick(items, options);
  }
  const item = items.find((i) => i.id === id);
  if (!item) {
    void vscode.window.showErrorMessage(
      `PCAP Lens: "${id}" isn't one of ${items.map((i) => `"${i.id}"`).join(", ")}.`,
    );
  }
  return item;
}

/** `args.dest`, else the save dialog's answer. */
function destination(
  args: ExportArgs,
  session: PcapEditorSession,
  suffix: string,
  ext: string,
  filters: Record<string, string[]>,
): Promise<string | undefined> {
  return args.dest !== undefined
    ? Promise.resolve(args.dest)
    : chooseDestination(session, suffix, ext, filters);
}

/** "PCAP: Export Specified Packets…": displayed / all / selected packets to pcapng or pcap. */
export async function exportFiltered(
  provider: PcapEditorProvider,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const filter = session.currentFilter.trim();
  const frames = session.openInfo?.frames ?? 0;
  type ScopeItem = vscode.QuickPickItem & {
    id: string;
    filter?: string;
    frames?: number[];
    suffix: string;
  };
  const scopes: ScopeItem[] = [
    {
      id: "displayed",
      label: "Displayed packets",
      description: filter
        ? `filter: ${filter}`
        : `no display filter: all ${frames.toLocaleString()} packets`,
      suffix: filter ? "filtered" : "export",
    },
    {
      id: "all",
      label: "All packets",
      description: `${frames.toLocaleString()} packets`,
      filter: "",
      suffix: "export",
    },
  ];
  const selected = session.selectedFrames;
  if (selected.length > 1) {
    scopes.push({
      id: "selected",
      label: "Selected packets",
      description: plural(selected.length, "packet"),
      frames: selected,
      suffix: "selected",
    });
  } else if (session.selectedFrame !== null) {
    scopes.push({
      id: "selected",
      label: "Selected packet only",
      description: `packet ${session.selectedFrame}`,
      filter: `frame.number == ${session.selectedFrame}`,
      suffix: `frame${session.selectedFrame}`,
    });
  }
  const scope = await choose(scopes, args.scope, {
    title: "Export Specified Packets (1/2)",
    placeHolder: "Which packets?",
  });
  if (!scope) {
    return undefined;
  }
  const format = await pickCaptureFormat("Export Specified Packets (2/2)", args.format);
  if (!format) {
    return undefined;
  }
  const dest = await destination(args, session, scope.suffix, format.ext, {
    [format.label]: [format.ext],
  });
  if (!dest) {
    return undefined;
  }
  const params: Record<string, unknown> = { kind: format.ext, dest };
  if (scope.frames) {
    params.frames = scope.frames;
  } else if (scope.filter !== undefined) {
    params.filter = scope.filter;
  }
  const result = await runExport(session, `Exporting packets to ${path.basename(dest)}`, params);
  if (result && !args.dest) {
    void reportExport(
      result,
      `${(result.packets ?? 0).toLocaleString()} packet${result.packets === 1 ? "" : "s"}`,
      true,
    );
  }
  return result;
}

/**
 * Save the packets a display filter picks (a VoIP call's SIP messages and
 * media) as a new pcapng file, asking where; `suffix` names the file
 * ("trace-call-1.pcapng").
 */
export async function exportFilterAs(
  session: PcapEditorSession,
  filter: string,
  suffix: string,
  what: string,
): Promise<ExportResult | undefined> {
  if (!backendOf(session)) {
    return undefined;
  }
  const dest = await chooseDestination(session, suffix, "pcapng", { pcapng: ["pcapng"] });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Saving ${what} to ${path.basename(dest)}`, {
    kind: "pcapng",
    dest,
    filter,
  });
  if (result) {
    void reportExport(result, `${what} (${plural(result.packets ?? 0, "packet")})`, true);
  }
  return result;
}

/** "PCAP: Export Marked Packets…": the packets marked with Ctrl+M to pcapng or pcap. */
export async function exportMarked(
  provider: PcapEditorProvider,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  if (!session.markedCount) {
    void vscode.window.showInformationMessage(
      "No packets are marked. Mark packets with Ctrl+M (Cmd+M) first.",
    );
    return undefined;
  }
  const format = await pickCaptureFormat(
    `Export ${plural(session.markedCount, "Marked Packet")}`,
    args.format,
  );
  if (!format) {
    return undefined;
  }
  const dest = await destination(args, session, "marked", format.ext, {
    [format.label]: [format.ext],
  });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting marked packets to ${path.basename(dest)}`, {
    kind: format.ext,
    dest,
    marked: true,
  });
  if (result && !args.dest) {
    void reportExport(
      result,
      `${(result.packets ?? 0).toLocaleString()} marked packet${result.packets === 1 ? "" : "s"}`,
      true,
    );
  }
  return result;
}

/** "PCAP: Export Selected Packets…": the packets selected in the list (Shift/Ctrl+click) to pcapng or pcap. */
export async function exportSelected(
  provider: PcapEditorProvider,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const frames = session.selectedFrames.length
    ? session.selectedFrames
    : session.selectedFrame !== null
      ? [session.selectedFrame]
      : [];
  if (!frames.length) {
    void vscode.window.showInformationMessage(
      "Select packets first (Shift+click or Ctrl+click selects several).",
    );
    return undefined;
  }
  const format = await pickCaptureFormat(
    `Export ${plural(frames.length, "Selected Packet")}`,
    args.format,
  );
  if (!format) {
    return undefined;
  }
  const dest = await destination(
    args,
    session,
    frames.length === 1 ? `frame${frames[0]}` : "selected",
    format.ext,
    { [format.label]: [format.ext] },
  );
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting selected packets to ${path.basename(dest)}`, {
    kind: format.ext,
    dest,
    frames,
  });
  if (result && !args.dest) {
    void reportExport(result, `${plural(result.packets ?? 0, "selected packet")}`, true);
  }
  return result;
}

/** "PCAP: Export Packet List as CSV/JSON…": the displayed (or selected) rows, in the current sort order, with their columns. */
export async function exportPacketList(
  provider: PcapEditorProvider,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const selected = session.selectedFrames;
  let frames: number[] | undefined;
  if (selected.length > 1 || args.scope !== undefined) {
    const scopes: (vscode.QuickPickItem & { id: string; frames?: number[] })[] = [
      {
        id: "displayed",
        label: "Displayed rows",
        description: session.currentFilter ? `filter: ${session.currentFilter}` : "all packets",
      },
    ];
    if (selected.length > 1) {
      scopes.push({
        id: "selected",
        label: "Selected rows",
        description: plural(selected.length, "row"),
        frames: selected,
      });
    }
    const scope = await choose(scopes, args.scope, {
      title: "Export Packet List",
      placeHolder: "Which rows?",
    });
    if (!scope) {
      return undefined;
    }
    frames = scope.frames;
  }
  const format = await choose(
    [
      {
        id: "csv",
        label: "CSV",
        description: "one quoted row per packet, like Wireshark",
        ext: "csv",
      },
      {
        id: "json",
        label: "JSON",
        description: "an array of objects keyed by column",
        ext: "json",
      },
    ],
    args.format,
    {
      title: "Export Packet List",
      placeHolder: session.currentFilter
        ? `Displayed packets (filter: ${session.currentFilter})`
        : "All packets",
    },
  );
  if (!format) {
    return undefined;
  }
  const dest = await destination(
    args,
    session,
    frames ? "selected-packets" : "packets",
    format.ext,
    { [format.label]: [format.ext] },
  );
  if (!dest) {
    return undefined;
  }
  const columns = readSettings(session.uri).columns;
  const result = await runExport(session, `Exporting packet list to ${path.basename(dest)}`, {
    kind: format.ext,
    dest,
    columns: columns.map((c) => c.field),
    titles: columns.map((c) => c.title),
    ...(frames ? { frames } : {}),
  });
  if (result && !args.dest) {
    void reportExport(result, `${(result.packets ?? 0).toLocaleString()} rows`, false);
  }
  return result;
}

/** "PCAP: Export Packet Dissections…": tshark's full packet details as plain text, PDML or JSON. */
export async function exportDissections(
  provider: PcapEditorProvider,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const title = "Export Packet Dissections";
  const filter = session.currentFilter.trim();
  const frames = session.openInfo?.frames ?? 0;
  type ScopeItem = vscode.QuickPickItem & {
    id: string;
    params: Record<string, unknown>;
    suffix: string;
  };
  const scopes: ScopeItem[] = [
    {
      id: "displayed",
      label: "Displayed packets",
      description: filter
        ? `filter: ${filter}`
        : `no display filter: all ${frames.toLocaleString()} packets`,
      params: {},
      suffix: filter ? "filtered" : "dissections",
    },
    {
      id: "all",
      label: "All packets",
      description: `${frames.toLocaleString()} packets`,
      params: { filter: "" },
      suffix: "dissections",
    },
  ];
  const selected = session.selectedFrames.length
    ? session.selectedFrames
    : session.selectedFrame !== null
      ? [session.selectedFrame]
      : [];
  if (selected.length) {
    const one = selected.length === 1;
    scopes.push({
      id: "selected",
      label: one ? "Selected packet" : "Selected packets",
      description: one ? `packet ${selected[0]}` : plural(selected.length, "packet"),
      params: { frames: selected },
      suffix: one ? `frame${selected[0]}` : "selected",
    });
  }
  if (session.markedCount) {
    scopes.push({
      id: "marked",
      label: "Marked packets",
      description: plural(session.markedCount, "packet"),
      params: { marked: true },
      suffix: "marked",
    });
  }
  const scope = await choose(scopes, args.scope, {
    title: `${title} (1/3)`,
    placeHolder: "Which packets?",
  });
  if (!scope) {
    return undefined;
  }
  const format = await choose(
    [
      {
        id: "text",
        label: "Plain text",
        description: "the packet details as in the tree (tshark -V)",
        format: "text",
        ext: "txt",
        name: "Text",
      },
      {
        id: "pdml",
        label: "PDML",
        description: "XML with every field (tshark -T pdml)",
        format: "pdml",
        ext: "pdml",
        name: "PDML",
      },
      {
        id: "json",
        label: "JSON",
        description: "an array of packets with every field (tshark -T json)",
        format: "json",
        ext: "json",
        name: "JSON",
      },
    ],
    args.format,
    { title: `${title} (2/3)`, placeHolder: "Format" },
  );
  if (!format) {
    return undefined;
  }
  // (tshark writes hex dumps only into text and JSON; PDML fields carry their bytes.)
  const contents =
    format.format === "pdml"
      ? { bytes: false }
      : args.bytes !== undefined
        ? { bytes: args.bytes }
        : await vscode.window.showQuickPick(
            [
              { label: "Packet details", bytes: false },
              {
                label: "Packet details and bytes",
                description: "adds each packet's hex dump",
                bytes: true,
              },
            ],
            { title: `${title} (3/3)`, placeHolder: "Contents" },
          );
  if (!contents) {
    return undefined;
  }
  const dest = await destination(args, session, scope.suffix, format.ext, {
    [format.name]: [format.ext],
    "All files": ["*"],
  });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(
    session,
    `Exporting packet dissections to ${path.basename(dest)}`,
    {
      kind: "dissections",
      format: format.format,
      bytes: contents.bytes,
      dest,
      ...scope.params,
    },
  );
  if (result && !args.dest) {
    void reportExport(result, `${plural(result.packets ?? 0, "packet")} (${format.label})`, false);
  }
  return result;
}

/** "PCAP: Export Packet Bytes…": raw bytes of the selected packet (or one of its reassembled sources). */
export async function exportPacketBytes(
  provider: PcapEditorProvider,
  frame?: number,
  rawArgs?: unknown,
): Promise<ExportResult | undefined> {
  const args = exportArgs(rawArgs);
  const session = requireSession(provider);
  const backend = session && backendOf(session);
  if (!session || !backend) {
    return undefined;
  }
  const number = typeof frame === "number" ? frame : session.selectedFrame;
  if (number === null) {
    void vscode.window.showInformationMessage("Select a packet to export its bytes.");
    return undefined;
  }
  let source = 0;
  try {
    const detail = await backend.request<{ sources: { name: string; hex: string }[] }>(
      "packet_detail",
      { number },
      { timeoutMs: 0 },
    );
    if (args.source !== undefined) {
      if (args.source < 0 || args.source >= detail.sources.length) {
        void vscode.window.showErrorMessage(
          `PCAP Lens: packet ${number} has ${plural(detail.sources.length, "data source")}.`,
        );
        return undefined;
      }
      source = args.source;
    } else if (detail.sources.length > 1) {
      const pick = await vscode.window.showQuickPick(
        detail.sources.map((s, i) => ({
          label: s.name,
          description: `${s.hex.length / 2} bytes`,
          index: i,
        })),
        { title: `Export Bytes of Packet ${number}`, placeHolder: "Which data?" },
      );
      if (!pick) {
        return undefined;
      }
      source = pick.index;
    }
  } catch (err) {
    void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    return undefined;
  }
  const dest = await destination(args, session, `frame${number}`, "bin", {
    "Raw bytes": ["bin"],
    "All files": ["*"],
  });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting bytes of packet ${number}`, {
    kind: "bytes",
    dest,
    number,
    source,
  });
  if (result && !args.dest) {
    void reportExport(
      result,
      `${(result.bytes ?? 0).toLocaleString()} bytes of packet ${number}`,
      false,
    );
  }
  return result;
}

/**
 * _PCAP: Export TLS Session Keys…_: the keys of the TLS sessions tshark could
 * decrypt, as a key log file (backend export_tls_keys). A capture without
 * decrypted sessions offers _Set TLS Key Log File…_ instead. `{dest}` skips
 * the save dialog (smoke test).
 */
export async function exportTlsKeys(
  provider: PcapEditorProvider,
  args?: { dest?: string },
): Promise<{ sessions: number; path: string } | undefined> {
  const session = requireSession(provider);
  const backend = session && backendOf(session);
  if (!session || !backend) {
    return undefined;
  }
  const dest =
    args?.dest ??
    (await chooseDestination(session, "tls-keys", "txt", {
      "Key log": ["txt", "keys", "log"],
      "All files": ["*"],
    }));
  if (!dest) {
    return undefined;
  }
  try {
    const result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: "PCAP: Exporting TLS session keys…" },
      () =>
        backend.request<{ sessions: number; path: string }>(
          "export_tls_keys",
          { dest },
          { timeoutMs: 0 },
        ),
    );
    if (!args?.dest) {
      const n = result.sessions;
      void reportExport(
        { ok: true, path: result.path, size: 0 },
        `the keys of ${n.toLocaleString()} TLS ${n === 1 ? "session" : "sessions"}`,
        false,
      );
    }
    return result;
  } catch (err) {
    if (err instanceof RpcError && (err.data as { empty?: boolean } | undefined)?.empty) {
      const set = "Set TLS Key Log File…";
      const choice = await vscode.window.showWarningMessage(`PCAP Lens: ${err.message}.`, set);
      if (choice === set) {
        await vscode.commands.executeCommand("pcapViewer.setTlsKeyLogFile");
      }
    } else {
      void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    }
    return undefined;
  }
}

export function registerExportCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.exportFiltered", (args?: unknown) =>
      exportFiltered(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.exportPacketList", (args?: unknown) =>
      exportPacketList(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.exportDissections", (args?: unknown) =>
      exportDissections(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.exportMarked", (args?: unknown) =>
      exportMarked(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.exportTlsKeys", (args?: { dest?: string }) =>
      exportTlsKeys(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.exportSelected", (args?: unknown) =>
      exportSelected(provider, args),
    ),
    // A frame number (the viewer's menu), or {frame, dest, source}.
    vscode.commands.registerCommand("pcapViewer.exportPacketBytes", (arg?: unknown) => {
      if (arg && typeof arg === "object") {
        const frame = (arg as { frame?: unknown }).frame;
        return exportPacketBytes(provider, typeof frame === "number" ? frame : undefined, arg);
      }
      return exportPacketBytes(provider, typeof arg === "number" ? arg : undefined);
    }),
  );
}
