import * as vscode from "vscode";
import { FOLLOW_COMMANDS, FOLLOW_LABELS, FollowPanel, FollowProto } from "../panels/followPanel";
import { FlowGraphPanel } from "../panels/flowGraphPanel";
import { ObjectsPanel } from "../panels/objectsPanel";
import { StatsKind, StatsPanel } from "../panels/statsPanel";
import { ComparePanel } from "../panels/comparePanel";
import { TcpGraphPanel } from "../panels/tcpGraphPanel";
import { VoipPanel } from "../panels/voipPanel";
import type { PcapEditorProvider } from "../pcapEditor";
import { requireSession } from "./filter";

const STATS_COMMANDS: Record<string, StatsKind> = {
  "pcapViewer.statistics.conversations": "conversations",
  "pcapViewer.statistics.endpoints": "endpoints",
  "pcapViewer.statistics.protocolHierarchy": "phs",
  "pcapViewer.statistics.ioGraph": "io",
  "pcapViewer.statistics.expertInfo": "expert",
  "pcapViewer.statistics.captureProperties": "properties",
  "pcapViewer.statistics.http": "http",
  "pcapViewer.statistics.dns": "dns",
  "pcapViewer.statistics.packetLengths": "plen",
  "pcapViewer.statistics.serviceResponseTime": "srt",
};

/** Follow-stream and statistics commands (brief 4.5 and 4.6). */
export function registerAnalysisCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  const follow = async (proto?: FollowProto, frame?: number) => {
    const session = requireSession(provider);
    if (!session) {
      return;
    }
    const target = typeof frame === "number" ? frame : session.selectedFrame;
    if (target === null || target === undefined) {
      void vscode.window.showInformationMessage("Select a packet in the stream to follow first.");
      return;
    }
    let chosen = proto;
    if (!chosen) {
      const pick = await vscode.window.showQuickPick(
        (Object.keys(FOLLOW_LABELS) as FollowProto[]).map((p) => ({
          label: `${FOLLOW_LABELS[p]} Stream`,
          proto: p,
        })),
        { title: `Follow Stream (packet ${target})` },
      );
      chosen = pick?.proto;
    }
    if (chosen) {
      FollowPanel.show(context, session, chosen, target);
    }
  };
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.followStream", (frame?: number) =>
      follow(undefined, frame),
    ),
    ...(Object.entries(FOLLOW_COMMANDS) as [FollowProto, string][]).map(([proto, command]) =>
      vscode.commands.registerCommand(command, (frame?: number) => follow(proto, frame)),
    ),
    ...Object.entries(STATS_COMMANDS).map(([command, kind]) =>
      vscode.commands.registerCommand(command, () => {
        const session = requireSession(provider);
        return session ? StatsPanel.show(context, session, kind) : undefined;
      }),
    ),
    vscode.commands.registerCommand("pcapViewer.statistics.tcpStreamGraph", (frame?: number) => {
      const session = requireSession(provider);
      const target = typeof frame === "number" ? frame : session?.selectedFrame;
      if (!session) {
        return undefined;
      }
      if (target === null || target === undefined) {
        void vscode.window.showInformationMessage("Select a packet of the TCP stream first.");
        return undefined;
      }
      return TcpGraphPanel.show(context, session, target);
    }),
    vscode.commands.registerCommand(
      "pcapViewer.comparePackets",
      async (args?: { frames?: unknown[] }) => {
        const session = requireSession(provider);
        if (!session) {
          return undefined;
        }
        const total = session.openInfo?.frames ?? 0;
        const valid = (n: unknown): n is number =>
          typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= total;
        // Two packets given (the row menu) or selected; else ask for the second one.
        let frames = (Array.isArray(args?.frames) ? args.frames : []).filter(valid);
        if (!frames.length) {
          if (session.selectedFrames.length > 2) {
            void vscode.window.showInformationMessage(
              `Select two packets to compare (${session.selectedFrames.length} are selected).`,
            );
            return undefined;
          }
          frames = session.selectedFrames.length
            ? session.selectedFrames
            : session.selectedFrame !== null
              ? [session.selectedFrame]
              : [];
        }
        if (!frames.length) {
          void vscode.window.showInformationMessage("Select a packet to compare first.");
          return undefined;
        }
        if (frames.length === 1) {
          const first = frames[0];
          const other = await vscode.window.showInputBox({
            title: "Compare Packets",
            prompt: `Compare packet ${first} with packet number…`,
            validateInput: (text) => {
              const n = Number(text.trim());
              return !valid(n)
                ? `A packet number from 1 to ${total.toLocaleString()}`
                : n === first
                  ? "Another packet than the one selected"
                  : undefined;
            },
          });
          if (other === undefined) {
            return undefined;
          }
          frames = [first, Number(other.trim())];
        }
        return ComparePanel.show(context, session, [frames[0], frames[1]]);
      },
    ),
    vscode.commands.registerCommand("pcapViewer.statistics.flowGraph", () => {
      const session = requireSession(provider);
      return session ? FlowGraphPanel.show(context, session) : undefined;
    }),
    vscode.commands.registerCommand("pcapViewer.statistics.voipCalls", () => {
      const session = requireSession(provider);
      return session ? VoipPanel.show(context, session) : undefined;
    }),
    vscode.commands.registerCommand("pcapViewer.exportObjects", () => {
      const session = requireSession(provider);
      return session ? ObjectsPanel.show(context, session) : undefined;
    }),
  );
}
