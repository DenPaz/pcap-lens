import * as path from "node:path";
import * as vscode from "vscode";
import type { PcapEditorSession } from "../pcapEditor";
import { exportFileName, safeFileName } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

/** A field's bytes as the viewer sends them (the detail's own bytes). */
export interface PacketBytes {
  frame: number;
  /** The field's name ("" for an unnamed node). */
  field: string;
  /** The tree line. */
  label: string;
  hex: string;
}

/** At most this many bytes (as hex digits: twice that) are taken from the viewer. */
const MAX_BYTES = 16 * 1024 * 1024;
const TEXT_EXTENSIONS = new Set(["txt", "c", "rs", "yaml", "html"]);

/** The viewer's message, checked (its data came from the capture). */
export function packetBytes(raw: unknown): PacketBytes | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const o = raw as Record<string, unknown>;
  const hex = typeof o.hex === "string" ? o.hex : "";
  if (
    !Number.isInteger(o.frame) ||
    (o.frame as number) < 1 ||
    hex.length % 2 ||
    hex.length > 2 * MAX_BYTES ||
    !/^[0-9a-fA-F]*$/.test(hex)
  ) {
    return undefined;
  }
  const text = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");
  return { frame: o.frame as number, field: text(o.field, 200), label: text(o.label, 1000), hex };
}

type FromPanel =
  | { type: "ready" }
  | { type: "goto" }
  /** Save the bytes the panel decoded (base64) or the text it shows. */
  | { type: "save"; base64?: string; text?: string; ext?: string }
  | { type: "copy"; text: string };

/**
 * Show Packet Bytes: one field's bytes, decoded (Base64, compressed, hex
 * digits, percent-encoding, quoted-printable, ROT13) and shown as text, a
 * hex dump, a C or Rust array, YAML or an image; saved raw or as shown. All
 * the decoding is in the panel (lib.decodeBytes, lib.bytesAs). One panel per
 * editor; showing it again shows the new field.
 */
export class BytesPanel {
  private static readonly open = new Map<number, BytesPanel>();

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    bytes: PacketBytes,
  ): BytesPanel {
    const existing = BytesPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      existing.bytes = bytes;
      existing.post({ type: "show", ...bytes });
      return existing;
    }
    const panel = new BytesPanel(context, session, bytes);
    BytesPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly BytesPanel[] {
    return [...BytesPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    public bytes: PacketBytes,
  ) {
    const title = `Packet Bytes · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.packetBytes",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "bytes.js", title);
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
        this.post({ type: "show", ...this.bytes });
        return;
      case "goto":
        this.session.goTo(this.bytes.frame);
        this.session.reveal();
        return;
      case "copy":
        await vscode.env.clipboard.writeText(String(msg.text ?? ""));
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
      case "save":
        return this.save(msg);
    }
  }

  private async save(msg: { base64?: string; text?: string; ext?: string }): Promise<void> {
    const raw = typeof msg.base64 === "string";
    const ext = raw ? "bin" : msg.ext && TEXT_EXTENSIONS.has(msg.ext) ? msg.ext : "txt";
    const name = safeFileName(`frame${this.bytes.frame}-${this.bytes.field || "bytes"}`);
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(exportFileName(this.session.uri.fsPath, name, ext)),
      title: `Save the bytes of ${this.bytes.field || "the field"} (packet ${this.bytes.frame})`,
      filters: raw
        ? { "Raw data": ["bin", "raw"], "All files": ["*"] }
        : { Text: [ext], "All files": ["*"] },
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
    BytesPanel.open.delete(this.session.id);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
