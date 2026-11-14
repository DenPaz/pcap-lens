import * as path from "node:path";
import * as vscode from "vscode";
import { type PcapEditorSession, describeError } from "../pcapEditor";
import { exportFileName, safeFileName } from "../settingsModel";
import { BytesPanel } from "./bytesPanel";
import { panelHtml, webviewRoot } from "./panelHtml";
import { panelColumn, placePanel } from "./placement";

/** Which exchange to show: HTTP Requests' row (its packets and messages). */
export interface HttpExchangeAsk {
  request: number;
  /** Which HTTP request of its packet (pipelined requests share one). */
  requestIndex: number;
  response: number | null;
  responseIndex: number;
  /** "GET www.example.com/index.html" */
  label: string;
}

/** One message as the backend's http_exchange gives it. */
export interface HttpMessage {
  frame: number;
  kind: "request" | "response";
  line: string;
  headers: [string, string][];
  /** The decoded body (de-chunked, decompressed), hex. */
  body: string;
  bodySize: number;
  truncated: boolean;
  decoded: boolean;
}

/** The statistics panel's message, checked (its numbers came from the backend's table). */
export function httpExchangeAsk(raw: unknown): HttpExchangeAsk | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const o = raw as Record<string, unknown>;
  const frame = (v: unknown) => Number.isInteger(v) && (v as number) > 0;
  const index = (v: unknown) => (Number.isInteger(v) && (v as number) >= 0 ? (v as number) : 0);
  if (
    !frame(o.request) ||
    (o.response !== null && o.response !== undefined && !frame(o.response))
  ) {
    return undefined;
  }
  return {
    request: o.request as number,
    requestIndex: index(o.requestIndex),
    response: frame(o.response) ? (o.response as number) : null,
    responseIndex: index(o.responseIndex),
    label: typeof o.label === "string" ? o.label.slice(0, 500) : "",
  };
}

type FromPanel =
  | { type: "ready" }
  | { type: "goto"; frame: number }
  | { type: "copy"; text: string }
  /** Save a body: its bytes (base64) or the text shown. */
  | { type: "save"; which: "request" | "response"; base64?: string; text?: string }
  /** Open a body in Show Packet Bytes (its other decodings and views). */
  | { type: "bytes"; which: "request" | "response" };

/**
 * One HTTP request and its response side by side: first lines, headers and
 * bodies (decoded by tshark: de-chunked, decompressed), the bodies shown
 * pretty-printed (JSON, XML, HTML, forms), as text, a hex dump or an image
 * (src/webview/http.js). Opened from HTTP Requests; one panel per editor,
 * showing it again shows the new exchange.
 */
export class HttpPanel {
  private static readonly open = new Map<number, HttpPanel>();

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    ask: HttpExchangeAsk,
  ): HttpPanel {
    const existing = HttpPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      existing.ask = ask;
      void existing.load();
      return existing;
    }
    const panel = new HttpPanel(context, session, ask);
    HttpPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly HttpPanel[] {
    return [...HttpPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The exchange shown (the smoke test reads it). */
  exchange: { request: HttpMessage | null; response: HttpMessage | null } | undefined;
  private readonly disposables: vscode.Disposable[] = [];
  private ready = false;
  private seq = 0;

  private constructor(
    private readonly context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    public ask: HttpExchangeAsk,
  ) {
    const title = `HTTP Exchange · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.httpExchange",
      title,
      panelColumn(session),
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.disposables.push(placePanel(this.panel, session));
    this.panel.webview.html = panelHtml(this.panel.webview, root, "http.js", title);
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

  /** Asks the backend for the exchange and shows it (a newer ask wins). */
  async load(): Promise<void> {
    if (!this.ready) {
      return; // ("ready" loads it)
    }
    const seq = ++this.seq;
    const ask = this.ask;
    this.post({ type: "loading", label: ask.label });
    const client = this.session.backend;
    try {
      if (!client?.running) {
        throw new Error("the capture's backend isn't running (reload the capture)");
      }
      const exchange = (await client.request("http_exchange", {
        request: ask.request,
        requestIndex: ask.requestIndex,
        response: ask.response,
        responseIndex: ask.responseIndex,
      })) as { request: HttpMessage | null; response: HttpMessage | null };
      if (seq !== this.seq) {
        return;
      }
      this.exchange = exchange;
      this.post({ type: "show", label: ask.label, ...exchange });
    } catch (err) {
      if (seq === this.seq) {
        this.post({ type: "error", message: `Couldn't read the exchange: ${describeError(err)}` });
      }
    }
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.ready = true;
        return this.load();
      case "goto":
        if (Number.isInteger(msg.frame) && msg.frame > 0) {
          this.session.goTo(msg.frame);
          this.session.reveal();
        }
        return;
      case "copy":
        await vscode.env.clipboard.writeText(String(msg.text ?? ""));
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
      case "save":
        return this.save(msg);
      case "bytes": {
        const message = this.message(msg.which);
        if (message?.body) {
          BytesPanel.show(this.context, this.session, {
            frame: message.frame,
            field: "http.file_data",
            label: `${message.kind === "request" ? "Request" : "Response"} body of ${
              this.ask.label || `packet ${message.frame}`
            }${message.truncated ? " (first 16 MB)" : ""}`,
            hex: message.body,
          });
        }
        return;
      }
    }
  }

  private message(which: unknown): HttpMessage | null {
    return which === "request" || which === "response" ? (this.exchange?.[which] ?? null) : null;
  }

  private async save(msg: { which: unknown; base64?: string; text?: string }): Promise<void> {
    const message = this.message(msg.which);
    if (!message) {
      return;
    }
    const raw = typeof msg.base64 === "string";
    const ext = raw ? "bin" : "txt";
    const name = safeFileName(`frame${message.frame}-${message.kind}-body`);
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(exportFileName(this.session.uri.fsPath, name, ext)),
      title: `Save the ${message.kind} body (packet ${message.frame})`,
      filters: raw ? { "All files": ["*"] } : { Text: ["txt"], "All files": ["*"] },
    });
    if (!target) {
      return;
    }
    const data = raw
      ? Buffer.from(msg.base64 as string, "base64")
      : Buffer.from(String(msg.text ?? ""), "utf8");
    await vscode.workspace.fs.writeFile(target, data);
    vscode.window.setStatusBarMessage(
      `Saved ${data.length.toLocaleString()} bytes to ${path.basename(target.fsPath)}`,
      4000,
    );
  }

  private dispose(): void {
    HttpPanel.open.delete(this.session.id);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
