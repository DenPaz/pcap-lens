import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { exportFileName } from "../settingsModel";
import { discardTemporaryCapture, newTemporaryCapture } from "../tempCaptures";
import { requireSession } from "./filter";

const LAST_TAP = "pcapViewer.exportPdusTap";

/** What the common export taps keep (tshark only names them). */
const TAP_HELP: Record<string, string> = {
  "OSI layer 3": "Each packet's network-layer payload, with its addresses",
  "OSI layer 4": "Each packet's transport payload, with its addresses and ports",
  "OSI layer 7": "Application messages that dissectors export (SIP, Diameter…)",
  IP: "The IP packets, without their link layer",
  Ethernet: "The Ethernet frames",
};

interface ExportPdusResult {
  pdus: number;
  frames: number;
  filter: string;
  path: string;
}

/**
 * _PCAP: Export PDUs to File…_ (Wireshark's File → Export PDUs to File): the
 * PDUs one of tshark's export taps collects from the displayed (or all)
 * packets, as a new unsaved capture. `{tap, filter}` skip the questions and
 * return the result (smoke test).
 */
async function exportPdus(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
  args?: { tap?: string; filter?: string },
): Promise<ExportPdusResult | undefined> {
  const session = requireSession(provider);
  const client = session?.backend;
  if (!session || !client?.running) {
    return undefined;
  }
  let tap = args?.tap;
  let filter = args?.filter;
  if (!tap) {
    const { taps } = await client.request<{ taps: { name: string; encapsulation: string }[] }>(
      "export_pdu_taps",
      {},
    );
    const last = context.globalState.get<string>(LAST_TAP) ?? "OSI layer 4";
    const items = taps
      .map((t) => ({
        label: t.name,
        description: t.encapsulation,
        detail: TAP_HELP[t.name],
        picked: t.name === last,
      }))
      .sort((a, b) => Number(b.picked) - Number(a.picked));
    const pick = await vscode.window.showQuickPick(items, {
      title: "Export PDUs to File",
      placeHolder: "Which PDUs? (the new capture's link type is on the right)",
    });
    if (!pick) {
      return undefined;
    }
    tap = pick.label;
    await context.globalState.update(LAST_TAP, tap);
  }
  if (filter === undefined) {
    const current = session.currentFilter;
    if (current) {
      const scope = await vscode.window.showQuickPick(
        [
          { label: "Displayed packets", description: current, filter: current },
          { label: "All packets", description: "", filter: "" },
        ],
        { title: `Export PDUs to File: ${tap}`, placeHolder: "From which packets?" },
      );
      if (!scope) {
        return undefined;
      }
      filter = scope.filter;
    } else {
      filter = "";
    }
  }
  const name = path.basename(exportFileName(session.uri.fsPath, "pdus", "pcapng"));
  const dest = await newTemporaryCapture(context, name);
  let result: ExportPdusResult;
  try {
    result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Exporting ${tap} PDUs: ${path.basename(session.uri.fsPath)}`,
        cancellable: true,
      },
      (_progress, token) => {
        const pending = client.send<ExportPdusResult>(
          "export_pdus",
          { tap, filter, dest },
          { timeoutMs: 0 },
        );
        token.onCancellationRequested(() => client.cancel(pending.id));
        return pending.promise;
      },
    );
  } catch (err) {
    discardTemporaryCapture(context, dest, 0);
    if (err instanceof RpcError && err.cancelled) {
      return undefined;
    }
    if (err instanceof RpcError && (err.data as { empty?: boolean } | undefined)?.empty) {
      void vscode.window.showInformationMessage(`PCAP Lens: ${err.message}.`);
      return undefined;
    }
    log.error(`export PDUs: ${describeError(err)}`);
    void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    return undefined;
  }
  await vscode.commands.executeCommand(
    "vscode.openWith",
    vscode.Uri.file(result.path),
    PcapEditorProvider.viewType,
  );
  vscode.window.setStatusBarMessage(
    `${result.pdus.toLocaleString()} ${tap} PDUs from ${result.frames.toLocaleString()} packets. Save the new capture to keep it.`,
    8000,
  );
  return result;
}

export function registerExportPdusCommand(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pcapViewer.exportPdus",
      (args?: { tap?: string; filter?: string }) => exportPdus(context, provider, log, args),
    ),
  );
}
