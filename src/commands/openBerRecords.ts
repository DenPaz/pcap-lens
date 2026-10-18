import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { discardTemporaryCapture, newTemporaryCapture } from "../tempCaptures";
import { pickFile } from "./openFile";
import { withBackend } from "./withBackend";

const TITLE = "Open BER Records as Packets";
/** The dissector chosen last (globalState). */
const LAST_DISSECTOR = "pcapViewer.berDissector";
/** What tshark calls a dissector (mirrors the backend's check). */
const DISSECTOR_RE = /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$/;

/** `{uri, dissector}` skip the questions (smoke test, Open File's and the editor's offers). */
export interface OpenBerRecordsArgs {
  uri?: vscode.Uri;
  dissector?: string;
}

interface SplitResult {
  path: string;
  packets: number;
  truncated: number;
  dissector: string;
}

type DissectorItem = vscode.QuickPickItem & { name: string };

/**
 * The dissector that decodes each record: tshark's named dissectors (Lua
 * ones included), the generic `ber` first, the last choice next; a name typed
 * that isn't listed can be used too (a Lua dissector this backend didn't load).
 */
async function pickDissector(
  context: vscode.ExtensionContext,
  names: { name: string; protocol: string }[],
): Promise<string | undefined> {
  const last = context.globalState.get<string>(LAST_DISSECTOR);
  const first = ["ber", ...(last && last !== "ber" ? [last] : [])];
  const byName = new Map(names.map((n) => [n.name, n.protocol]));
  const item = (name: string): DissectorItem => ({
    name,
    label: name,
    description: byName.get(name) ?? "",
    detail:
      name === "ber"
        ? "Generic BER: the tags, lengths and values of each record"
        : name === last
          ? "Chosen last time"
          : undefined,
  });
  const listed: DissectorItem[] = [
    ...first.map(item),
    ...names.filter((n) => !first.includes(n.name)).map((n) => item(n.name)),
  ];
  const qp = vscode.window.createQuickPick<DissectorItem>();
  qp.title = TITLE;
  qp.placeholder = "Dissector that decodes each record (type to search, or a dissector's name)";
  qp.matchOnDescription = true;
  qp.items = listed;
  qp.onDidChangeValue((value) => {
    const typed = value.trim();
    const custom =
      DISSECTOR_RE.test(typed) && !byName.has(typed) && !first.includes(typed)
        ? [{ name: typed, label: typed, description: "use this name", alwaysShow: true }]
        : [];
    qp.items = [...custom, ...listed];
  });
  const chosen = await new Promise<string | undefined>((resolve) => {
    qp.onDidAccept(() => resolve((qp.selectedItems[0] ?? qp.activeItems[0])?.name));
    qp.onDidHide(() => resolve(undefined));
    qp.show();
  });
  qp.dispose();
  return chosen;
}

/** "cdrs.dat" → "cdrs.pcapng". */
export function splitFileName(file: string): string {
  const parsed = path.parse(file);
  return `${parsed.name || parsed.base}.pcapng`;
}

/**
 * PCAP: Open BER Records as Packets…: a file of BER values back to back
 * (which tshark refuses) becomes an unsaved capture with one packet per
 * record, each decoded by the chosen dissector (backend `split_ber`).
 * Returns the new capture's path.
 */
export async function openBerRecords(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  args?: OpenBerRecordsArgs,
): Promise<string | undefined> {
  const uri = args?.uri instanceof vscode.Uri ? args.uri : await pickFile(TITLE);
  if (!uri) {
    return undefined;
  }
  if (uri.scheme !== "file") {
    void vscode.window.showWarningMessage(
      `PCAP Lens: ${path.basename(uri.path)} isn't a file on disk; open a copy of it instead.`,
    );
    return undefined;
  }
  let dest: string | undefined;
  try {
    const result = await withBackend(provider, context, log, async (client) => {
      let dissector = args?.dissector;
      if (!dissector) {
        const { dissectors } = await client.request<{
          dissectors: { name: string; protocol: string }[];
        }>("dissector_names", {}, { timeoutMs: 60_000 });
        dissector = await pickDissector(context, dissectors);
        if (!dissector) {
          return undefined;
        }
        await context.globalState.update(LAST_DISSECTOR, dissector);
      }
      dest = await newTemporaryCapture(context, splitFileName(uri.fsPath));
      const target = dest;
      return vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `${TITLE}: ${path.basename(uri.fsPath)}`,
          cancellable: true,
        },
        (progress, token) => {
          let done = 0;
          const pending = client.send<SplitResult>(
            "split_ber",
            { path: uri.fsPath, dest: target, dissector },
            {
              timeoutMs: 0,
              onProgress: (p: { fraction?: number | null }) => {
                if (typeof p.fraction === "number") {
                  const pct = Math.round(p.fraction * 100);
                  progress.report({ increment: pct - done });
                  done = pct;
                }
              },
            },
          );
          token.onCancellationRequested(() => client.cancel(pending.id));
          return pending.promise;
        },
      );
    });
    if (!result) {
      if (dest) {
        discardTemporaryCapture(context, dest, 0);
      }
      return undefined;
    }
    await vscode.commands.executeCommand(
      "vscode.openWith",
      vscode.Uri.file(result.path),
      PcapEditorProvider.viewType,
    );
    const packets = `${result.packets.toLocaleString()} record${result.packets === 1 ? "" : "s"}`;
    vscode.window.setStatusBarMessage(
      `Opened ${packets} as packets (dissector ${result.dissector}). Save the new capture to keep it.`,
      8000,
    );
    if (result.truncated) {
      void vscode.window.showWarningMessage(
        `PCAP Lens: ${result.truncated.toLocaleString()} record${result.truncated === 1 ? " is" : "s are"} ` +
          "longer than 256 KiB, the most tshark reads in one packet; only their start is shown.",
      );
    }
    return result.path;
  } catch (err) {
    if (dest) {
      discardTemporaryCapture(context, dest, 0);
    }
    if (!(err instanceof RpcError && err.cancelled)) {
      log.error(`open BER records ${uri.fsPath}: ${describeError(err)}`);
      void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    }
    return undefined;
  }
}

export function registerOpenBerRecordsCommand(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.openBerRecords", (args?: OpenBerRecordsArgs) =>
      openBerRecords(provider, context, log, args),
    ),
  );
}
