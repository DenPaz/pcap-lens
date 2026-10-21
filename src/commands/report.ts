import * as path from "node:path";
import * as vscode from "vscode";
import type { CaptureFacts, StatsTable } from "../aiSummary";
import {
  REPORT_LIMITS,
  ReportFormat,
  ReportPackets,
  buildReport,
  reportFileName,
} from "../captureReport";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { requireSession } from "./filter";

interface ReportArgs {
  format?: ReportFormat;
  packets?: boolean;
  dest?: string;
}

/**
 * "PCAP: Capture Report…": the capture's properties, protocol hierarchy, top
 * conversations and endpoints, expert information and, if asked, the
 * displayed packets, as a Markdown or HTML file (no AI, nothing leaves the
 * machine). `{format, packets, dest}` skip the questions (smoke test).
 */
async function captureReport(
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
  args?: ReportArgs,
): Promise<string | undefined> {
  const session = requireSession(provider);
  const backend = session?.backend;
  if (!session || !backend?.running) {
    return undefined;
  }
  let format = args?.format;
  if (format !== "markdown" && format !== "html") {
    const pick = await vscode.window.showQuickPick(
      [
        {
          label: "Markdown",
          description: ".md: readable as text, renders on GitHub",
          id: "markdown" as const,
        },
        {
          label: "HTML",
          description: ".html: one file that opens in any browser",
          id: "html" as const,
        },
      ],
      { title: "Capture Report", placeHolder: "Which format?" },
    );
    if (!pick) {
      return undefined;
    }
    format = pick.id;
  }
  let withPackets = args?.packets;
  if (withPackets === undefined) {
    const filter = session.currentFilter;
    const pick = await vscode.window.showQuickPick(
      [
        { label: "Statistics only", packets: false },
        {
          label: "Statistics and the packet list",
          description: filter ? `the packets matching ${filter}` : "every packet",
          detail: `At most ${REPORT_LIMITS.packets.toLocaleString()} packets, with the list's columns`,
          packets: true,
        },
      ],
      { title: "Capture Report", placeHolder: "What should it hold?" },
    );
    if (!pick) {
      return undefined;
    }
    withPackets = pick.packets;
  }
  let dest = args?.dest;
  if (!dest) {
    const capture = session.uri.fsPath;
    const uri = await vscode.window.showSaveDialog({
      title: "Save Capture Report",
      defaultUri: vscode.Uri.file(
        path.join(path.dirname(capture), reportFileName(path.basename(capture), format)),
      ),
      filters: format === "html" ? { HTML: ["html"] } : { Markdown: ["md"] },
    });
    if (!uri) {
      return undefined;
    }
    dest = uri.fsPath;
  }
  try {
    const text = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Capture report: computing statistics with tshark…",
        cancellable: false,
      },
      async () => {
        const missing: string[] = [];
        const stats = (name: string, params: Record<string, unknown>) =>
          backend.request<StatsTable>("stats", params, { timeoutMs: 0 }).catch((err: unknown) => {
            log.info(`capture report: ${name} failed: ${describeError(err)}`);
            missing.push(name);
            return undefined;
          });
        const [info, protocols, tcp, udp, endpoints, expert, packets] = await Promise.all([
          backend.request<CaptureFacts>("capture_info", {}),
          stats("protocol hierarchy", { kind: "phs" }),
          stats("TCP conversations", { kind: "conversations", type: "tcp" }),
          stats("UDP conversations", { kind: "conversations", type: "udp" }),
          stats("endpoints", { kind: "endpoints", type: "ip" }),
          stats("expert information", { kind: "expert" }),
          withPackets
            ? backend
                .request<ReportPackets>(
                  "list_packets",
                  { offset: 0, limit: REPORT_LIMITS.packets, timeFormat: "relative" },
                  { timeoutMs: 0 },
                )
                .catch((err: unknown) => {
                  log.info(`capture report: packets failed: ${describeError(err)}`);
                  missing.push("packet list");
                  return undefined;
                })
            : Promise.resolve(undefined),
        ]);
        return buildReport(
          {
            name: path.basename(session.uri.fsPath),
            path: session.uri.fsPath,
            generated: new Date(),
            filter: session.currentFilter,
            info,
            protocols,
            conversations: [
              ...(tcp ? [{ title: "TCP conversations", table: tcp }] : []),
              ...(udp ? [{ title: "UDP conversations", table: udp }] : []),
            ],
            endpoints: endpoints ? [{ title: "IPv4 endpoints", table: endpoints }] : [],
            expert,
            packets,
            missing,
          },
          format,
        );
      },
    );
    await vscode.workspace.fs.writeFile(vscode.Uri.file(dest), new TextEncoder().encode(text));
  } catch (err) {
    log.error(`capture report: ${describeError(err)}`);
    void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    return undefined;
  }
  if (!args?.dest) {
    const open = format === "html" ? "Open in Browser" : "Open";
    const pick = await vscode.window.showInformationMessage(
      `PCAP Lens: saved the capture report ${path.basename(dest)}.`,
      open,
    );
    if (pick === open && format === "html") {
      await vscode.env.openExternal(vscode.Uri.file(dest));
    } else if (pick === open) {
      await vscode.commands.executeCommand("markdown.showPreview", vscode.Uri.file(dest));
    }
  }
  return dest;
}

export function registerReportCommand(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.captureReport", (args?: ReportArgs) =>
      captureReport(provider, log, args),
    ),
  );
}
