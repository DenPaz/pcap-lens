import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel = { type: "ready" } | { type: "goto"; frame: number } | { type: "swap" };

/** One packet as the panel shows it (packet_detail's tree). */
export interface ComparedPacket {
  number: number;
  tree: unknown[];
  twoPass?: boolean;
}

/**
 * Compare Packets: two packets' details side by side, the fields that differ
 * marked (lib.comparePackets in the panel). One panel per editor; showing it
 * again compares the new pair.
 */
export class ComparePanel {
  private static readonly open = new Map<number, ComparePanel>();

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    frames: [number, number],
  ): ComparePanel {
    const existing = ComparePanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      existing.frames = frames;
      void existing.load();
      return existing;
    }
    const panel = new ComparePanel(context, session, frames);
    ComparePanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly ComparePanel[] {
    return [...ComparePanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The packets shown last (for tests). */
  current: [ComparedPacket, ComparedPacket] | undefined;
  private ready = false;
  private seq = 0;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    private frames: [number, number],
  ) {
    const title = `Compare Packets · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.compare",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "compare.js", title);
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
        this.ready = true;
        return this.load();
      case "swap":
        this.frames = [this.frames[1], this.frames[0]];
        return this.load();
      case "goto":
        if (Number.isInteger(msg.frame) && msg.frame > 0) {
          this.session.goTo(msg.frame);
        }
        return;
    }
  }

  /** Fetch both packets' details and show them (a newer request wins). */
  private async load(): Promise<void> {
    if (!this.ready) {
      return; // "ready" loads them
    }
    const seq = ++this.seq;
    const client = this.session.backend;
    const [a, b] = this.frames;
    this.post({ type: "loading", frames: this.frames });
    if (!client?.running) {
      this.post({
        type: "error",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    try {
      const packets = await Promise.all(
        [a, b].map((n) =>
          client.request<ComparedPacket>("packet_detail", this.session.detailParams(n), {
            timeoutMs: 0,
          }),
        ),
      );
      if (seq !== this.seq) {
        return;
      }
      this.current = [packets[0], packets[1]];
      this.post({ type: "show", a: packets[0], b: packets[1] });
    } catch (err) {
      if (seq === this.seq) {
        const e =
          err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
        this.post({ type: "error", message: e.message });
      }
    }
  }

  private dispose(): void {
    ComparePanel.open.delete(this.session.id);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
