import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { filterOutExpr } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

export type FollowProto = "tcp" | "udp" | "tls" | "http" | "http2" | "quic" | "websocket";

export const FOLLOW_LABELS: Record<FollowProto, string> = {
  tcp: "TCP",
  udp: "UDP",
  tls: "TLS",
  http: "HTTP",
  http2: "HTTP/2",
  quic: "QUIC",
  websocket: "WebSocket",
};

/** The "Follow <proto> Stream" command of each protocol. */
export const FOLLOW_COMMANDS: Record<FollowProto, string> = {
  tcp: "pcapViewer.followTcpStream",
  udp: "pcapViewer.followUdpStream",
  tls: "pcapViewer.followTlsStream",
  http: "pcapViewer.followHttpStream",
  http2: "pcapViewer.followHttp2Stream",
  quic: "pcapViewer.followQuicStream",
  websocket: "pcapViewer.followWebSocketStream",
};

/** Extensions a stream saved as text may get (the panel names one per view). */
const TEXT_EXTENSIONS = new Set(["txt", "c", "yaml"]);

export interface FollowResult {
  proto: FollowProto;
  stream: number;
  filter: string;
  nodes: [string, string];
  segments: { dir: 0 | 1; hex: string }[];
  bytes: [number, number];
  truncated: boolean;
  hint?: string;
  /** HTTP/2 and QUIC: the sub-stream followed and those the connection has. */
  substream?: number;
  substreams?: number[];
}

type FromPanel =
  | { type: "ready" }
  | { type: "stream"; stream: number; substream?: number }
  | { type: "filter"; expr: string; apply: boolean }
  /** "Filter Out This Stream": every packet but the stream's (the host knows the display filter). */
  | { type: "filterOut"; expr: string }
  | {
      type: "save";
      dir: "both" | 0 | 1;
      format: "raw" | "text";
      text?: string;
      /** For text: "txt", "c" (C arrays) or "yaml". */
      ext?: string;
    };

/**
 * "Follow Stream": the reassembled payload of one conversation, colored by
 * direction, with a direction filter, stream stepping and save-to-file.
 */
export class FollowPanel {
  static readonly panels = new Set<FollowPanel>();

  readonly panel: vscode.WebviewPanel;
  private result?: FollowResult;
  private requestId?: number;
  private readonly disposables: vscode.Disposable[] = [];

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    proto: FollowProto,
    frame: number,
  ): FollowPanel {
    const panel = new FollowPanel(context, session, proto, { frame });
    FollowPanel.panels.add(panel);
    return panel;
  }

  private constructor(
    context: vscode.ExtensionContext,
    private readonly session: PcapEditorSession,
    private readonly proto: FollowProto,
    private target: { frame?: number; stream?: number; substream?: number },
  ) {
    const title = `Follow ${FOLLOW_LABELS[proto]} Stream · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.follow",
      title,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [root],
        retainContextWhenHidden: true,
      },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "follow.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidDispose(() => this.panel.dispose()),
    );
  }

  /** Last loaded stream (for tests). */
  get current(): FollowResult | undefined {
    return this.result;
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        return this.load();
      case "stream":
        this.target =
          typeof msg.substream === "number"
            ? { stream: msg.stream, substream: msg.substream }
            : { stream: msg.stream };
        return this.load();
      case "filter":
        if (msg.apply) {
          this.session.applyFilter(msg.expr);
        } else {
          this.session.prepareFilter(msg.expr);
        }
        this.session.reveal();
        return;
      case "filterOut":
        this.session.applyFilter(filterOutExpr(this.session.currentFilter, msg.expr));
        this.session.reveal();
        return;
      case "save":
        return this.save(msg.dir, msg.format, msg.text, msg.ext);
    }
  }

  private async load(): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    if (this.requestId !== undefined) {
      client.cancel(this.requestId);
    }
    this.post({ type: "loading" });
    const pending = client.send<FollowResult>(
      "follow_stream",
      { proto: this.proto, ...this.target },
      { timeoutMs: 0 },
    );
    this.requestId = pending.id;
    try {
      this.result = await pending.promise;
      this.post({ type: "result", result: this.result, label: FOLLOW_LABELS[this.proto] });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      if (!e.cancelled) {
        this.post({ type: "error", message: e.message });
      }
    } finally {
      if (this.requestId === pending.id) {
        this.requestId = undefined;
      }
    }
  }

  /** Save the stream: raw bytes of the chosen direction(s), or the text the panel shows. */
  private async save(
    dir: "both" | 0 | 1,
    format: "raw" | "text",
    text?: string,
    ext?: string,
  ): Promise<void> {
    const result = this.result;
    if (!result) {
      return;
    }
    const sub = typeof result.substream === "number" ? `-${result.substream}` : "";
    const base = `${result.proto}-stream-${result.stream}${sub}${dir === "both" ? "" : dir === 0 ? "-client" : "-server"}`;
    const textExt = ext && TEXT_EXTENSIONS.has(ext) ? ext : "txt";
    const folder = vscode.Uri.file(path.dirname(this.session.uri.fsPath));
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.joinPath(folder, `${base}.${format === "raw" ? "bin" : textExt}`),
      title: `Save ${FOLLOW_LABELS[result.proto]} stream ${result.stream}`,
      filters:
        format === "raw"
          ? { "Raw data": ["bin", "raw"], "All files": ["*"] }
          : { Text: [textExt], "All files": ["*"] },
    });
    if (!target) {
      return;
    }
    const data =
      format === "raw"
        ? Buffer.concat(
            result.segments
              .filter((s) => dir === "both" || s.dir === dir)
              .map((s) => Buffer.from(s.hex, "hex")),
          )
        : Buffer.from(text ?? "", "utf8");
    await vscode.workspace.fs.writeFile(target, data);
    vscode.window.setStatusBarMessage(
      `Saved ${data.length.toLocaleString()} bytes to ${path.basename(target.fsPath)}`,
      4000,
    );
  }

  private dispose(): void {
    FollowPanel.panels.delete(this);
    if (this.requestId !== undefined) {
      this.session.backend?.cancel(this.requestId);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
