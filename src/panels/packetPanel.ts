import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel =
  | { type: "ready" }
  | { type: "filter"; expr: string; apply: boolean }
  | { type: "copy"; text: string }
  | { type: "goto"; frame: number };

/** What the panel shows: one packet's detail, or the capture file's own structure. */
export type PacketView = { kind: "packet"; frame: number } | { kind: "file" };

interface Detail {
  tree: unknown[];
  sources: { name: string; hex: string }[];
}

interface FileFormat extends Detail {
  format: string;
  size: number;
  shown: number;
  truncated: boolean;
}

/** The note above a file's structure when only its start is shown. */
export function fileFormatNote(f: Pick<FileFormat, "size" | "shown" | "truncated">): string {
  return f.truncated
    ? `Only the first ${f.shown.toLocaleString()} of ${f.size.toLocaleString()} bytes are shown: the rest of the file's records are left out.`
    : "";
}

/**
 * Show Packet in New Window (one packet's detail and bytes, which stay when
 * the selection moves) and the File Format view (Wireshark's Reload as File
 * Format: the capture file's headers and blocks as a tree over its bytes).
 * One panel per (editor, view); showing it again reveals it.
 */
export class PacketPanel {
  private static readonly open = new Map<string, PacketPanel>();

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    view: PacketView,
  ): PacketPanel {
    const key = `${session.id}:${view.kind === "file" ? "file" : view.frame}`;
    const existing = PacketPanel.open.get(key);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new PacketPanel(context, session, view, key);
    PacketPanel.open.set(key, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly PacketPanel[] {
    return [...PacketPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** What was shown last (for tests). */
  current: { title: string; note?: string; tree: unknown[] } | undefined;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    readonly view: PacketView,
    private readonly key: string,
  ) {
    const name = path.basename(session.uri.fsPath);
    const title = view.kind === "file" ? `File Format · ${name}` : `Packet ${view.frame} · ${name}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.packet",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "packet.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidDispose(() => this.panel.dispose()),
    );
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        return this.load();
      case "filter":
        if (typeof msg.expr === "string" && msg.expr) {
          if (msg.apply) {
            this.session.applyFilter(msg.expr);
          } else {
            this.session.prepareFilter(msg.expr);
          }
        }
        return;
      case "copy":
        await vscode.env.clipboard.writeText(String(msg.text ?? ""));
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
      case "goto":
        if (this.view.kind === "packet") {
          this.session.goTo(this.view.frame);
          this.session.reveal();
        }
        return;
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
    try {
      if (this.view.kind === "packet") {
        const { frame } = this.view;
        const detail = await client.request<Detail & { twoPass?: boolean }>(
          "packet_detail",
          this.session.detailParams(frame),
          { timeoutMs: 0 },
        );
        this.current = { title: `Packet ${frame}`, tree: detail.tree };
        this.post({ type: "show", ...this.current, frame, sources: detail.sources });
      } else {
        const f = await client.request<FileFormat>("file_format", {}, { timeoutMs: 0 });
        const note = fileFormatNote(f) || undefined;
        this.current = { title: f.format, note, tree: f.tree };
        this.post({ type: "show", ...this.current, sources: f.sources, expand: false });
      }
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      this.post({ type: "error", message: e.message });
    }
  }

  private dispose(): void {
    PacketPanel.open.delete(this.key);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
