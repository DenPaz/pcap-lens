import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel =
  | { type: "ready" }
  | { type: "query"; id: number; limit?: boolean }
  | { type: "filter"; expr: string; apply: boolean }
  | { type: "copy"; text: string }
  /** A card's "Open …": the full statistics it summarises. */
  | { type: "command"; id: string };

/** The commands a card may open (anything else the panel posts is ignored). */
export const OVERVIEW_COMMANDS: ReadonlySet<string> = new Set([
  "pcapViewer.statistics.captureProperties",
  "pcapViewer.statistics.expertInfo",
  "pcapViewer.statistics.ioGraph",
  "pcapViewer.statistics.endpoints",
  "pcapViewer.statistics.protocolHierarchy",
  "pcapViewer.statistics.conversations",
  "pcapViewer.statistics.httpRequests",
  "pcapViewer.statistics.dnsQueries",
  "pcapViewer.statistics.tlsServers",
]);

/**
 * The capture at a glance: the backend's `overview` (one pass), its
 * properties and expert counts as cards. One panel per editor; showing it
 * again reveals it. It counts once the capture is completely read.
 */
export class OverviewPanel {
  private static readonly open = new Map<number, OverviewPanel>();

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): OverviewPanel {
    const existing = OverviewPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new OverviewPanel(context, session);
    OverviewPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly OverviewPanel[] {
    return [...OverviewPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The last overview shown (for tests). */
  current: Record<string, unknown> | undefined;
  private readonly inflight = new Set<number>();
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `Capture Overview · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.overview",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "overview.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidChangeFilter((filter) => this.post({ type: "filterChanged", filter })),
      session.onDidDispose(() => this.panel.dispose()),
    );
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.post({ type: "init", filter: this.session.currentFilter });
        return;
      case "query":
        return this.query(msg.id, msg.limit === true);
      case "filter":
        if (typeof msg.expr !== "string") {
          return;
        }
        if (msg.apply) {
          this.session.applyFilter(msg.expr);
        } else {
          this.session.prepareFilter(msg.expr);
        }
        this.session.reveal();
        return;
      case "copy":
        if (typeof msg.text === "string") {
          await vscode.env.clipboard.writeText(msg.text);
          vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        }
        return;
      case "command":
        if (OVERVIEW_COMMANDS.has(msg.id)) {
          this.session.activate();
          await vscode.commands.executeCommand(msg.id);
        }
        return;
    }
  }

  private async query(id: number, limit: boolean): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        id,
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    // (Counted once every packet is read: a capture still being read isn't cached.)
    let read = false;
    const indexed = this.session.whenIndexed().then(() => (read = true));
    await Promise.resolve();
    if (!read) {
      this.post({ type: "progress", id, fraction: null, message: "Waiting for the packets…" });
    }
    await indexed;
    const filter = limit ? this.session.currentFilter : "";
    const pending = client.send(
      "overview",
      { filter },
      {
        timeoutMs: 0,
        onProgress: (p) => this.post({ type: "progress", id, fraction: p.fraction ?? null }),
      },
    );
    this.inflight.add(pending.id);
    // (Neither is needed for the cards: a failure leaves its tiles out.)
    const info = client.request<Record<string, unknown>>("capture_info", {}).catch(() => null);
    const expert = client
      .request<{ counts: Record<string, number> }>("expert_summary", {}, { timeoutMs: 0 })
      .then((r) => r.counts)
      .catch(() => null);
    try {
      const overview = await pending.promise;
      this.current = overview as Record<string, unknown>;
      this.post({ type: "result", id, overview, info: await info, expert: await expert });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      this.post({ type: "error", id, message: e.message, cancelled: e.cancelled });
    } finally {
      this.inflight.delete(pending.id);
    }
  }

  private dispose(): void {
    OverviewPanel.open.delete(this.session.id);
    for (const backendId of this.inflight) {
      this.session.backend?.cancel(backendId);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
