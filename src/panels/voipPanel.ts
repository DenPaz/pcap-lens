import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { VoipCallData, callSummary } from "../aiAnomaly";
import { exportFilterAs } from "../commands/export";
import { revealFile, revealLabel } from "../commands/reveal";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { audioFileName, exportFileName } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

/** A media stream as the backend's voip_calls lists it: RTP, or an IAX2 call's voice frames. */
export interface RtpStream {
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  ssrc: string;
  payload: string;
  packets: number;
  lost: number;
  filter: string;
  heuristic?: boolean;
  /** IAX2 voice: tshark's call identifier (the stream key then has SSRC 0). */
  iax2?: number;
  /** The call's SDP rtpmap ({"96": "G726-32/8000"}): how to decode dynamic types. */
  rtpmap?: Record<string, string>;
}

/** A call's stream as call_audio takes it: 0 = the caller's (left), 1 = the callee's. */
type CallStream = RtpStream & { channel: 0 | 1; start: number };

/** A call as the backend's voip_calls lists it (voip.py, voip_protocols.py). */
export interface VoipCall extends VoipCallData {
  id: number;
  callId: string;
  quality: { mos: number; r: number; rating: string; stream: number } | null;
  filter: string;
}

type FromPanel =
  | { type: "ready" }
  | { type: "list"; heuristic: boolean }
  | { type: "analyse"; id: number; stream: RtpStream }
  | { type: "play"; id: number; stream: RtpStream }
  | { type: "save"; stream: RtpStream; format: "wav" | "raw" }
  | { type: "filter"; expr: string }
  | { type: "saveCall"; call: { id: number; filter: string } }
  | { type: "playCall"; id: number; call: number; streams: CallStream[] }
  | { type: "saveCallAudio"; call: number; streams: CallStream[] }
  | { type: "askCopilot"; call: number }
  | { type: "goto"; frame: number };

/**
 * VoIP calls of one capture: the SIP, H.323, MGCP and IAX2 calls (with their
 * message flow, media, timings, quality, DTMF and media problems; one can be
 * saved alone), the media streams (packets, loss, jitter, MOS), a stream's packet-by-packet
 * analysis, and its audio, played in the panel or saved as WAV. The backend
 * does the passes and the decoding; audio reaches the webview as a file in
 * this panel's own folder (never through postMessage).
 */
export class VoipPanel {
  private static readonly open = new Map<number, VoipPanel>();

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): VoipPanel {
    const existing = VoipPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new VoipPanel(context, session);
    VoipPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly VoipPanel[] {
    return [...VoipPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The last list received (for tests). */
  calls: { calls: VoipCall[]; streams: RtpStream[]; registrations?: unknown[] } | undefined;
  private listing: number | undefined;
  /** Where played audio is written (removed with the panel). */
  private readonly audioDir: string;
  private audioSeq = 0;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `VoIP Calls · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    // A file: path (the backend writes it; globalStorageUri may be vscode-userdata:).
    this.audioDir = path.join(
      context.globalStorageUri.fsPath,
      "audio",
      crypto.randomBytes(8).toString("hex"),
    );
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.voip",
      title,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [root, vscode.Uri.file(this.audioDir)],
        retainContextWhenHidden: true,
      },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "voip.js", title, {
      media: true,
    });
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
        this.post({
          type: "init",
          title: `VoIP Calls · ${path.basename(this.session.uri.fsPath)}`,
          ai: await this.session.aiAvailable(),
        });
        return this.list(false);
      case "list":
        return this.list(msg.heuristic === true);
      case "analyse":
        return this.analyse(msg.id, msg.stream);
      case "play":
        return this.play(msg.id, msg.stream);
      case "save":
        return this.save(msg.stream, msg.format === "raw" ? "raw" : "wav");
      case "filter":
        if (typeof msg.expr === "string" && msg.expr) {
          this.session.applyFilter(msg.expr);
          this.session.reveal();
        }
        return;
      case "saveCall":
        if (typeof msg.call?.filter === "string" && msg.call.filter) {
          const n = Number(msg.call.id) + 1;
          await exportFilterAs(this.session, msg.call.filter, `call-${n}`, `call ${n}`);
        }
        return;
      case "playCall":
        return Number.isInteger(msg.call) && Array.isArray(msg.streams)
          ? this.playCall(msg.id, msg.call, msg.streams)
          : undefined;
      case "saveCallAudio":
        return Number.isInteger(msg.call) && Array.isArray(msg.streams)
          ? this.saveCallAudio(msg.call, msg.streams)
          : undefined;
      case "askCopilot": {
        // From the list this host received, not from the webview's copy.
        const call = Number.isInteger(msg.call) ? this.calls?.calls[msg.call] : undefined;
        if (call && this.calls) {
          await vscode.commands.executeCommand("pcapViewer.askAboutAnomaly", {
            kind: "call",
            call: callSummary(call, this.calls.streams),
            sessionId: this.session.id,
          });
        }
        return;
      }
      case "goto":
        this.session.goTo(msg.frame);
        this.session.reveal();
        return;
    }
  }

  private backend() {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return undefined;
    }
    return client;
  }

  private async list(heuristic: boolean): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    if (this.listing !== undefined) {
      client.cancel(this.listing);
    }
    const pending = client.send<{ calls: VoipCall[]; streams: RtpStream[] }>(
      "voip_calls",
      { heuristic },
      { timeoutMs: 0 },
    );
    this.listing = pending.id;
    try {
      const result = await pending.promise;
      this.calls = result;
      this.post({ type: "calls", ...result, heuristic });
    } catch (err) {
      this.postError(err);
    } finally {
      if (this.listing === pending.id) {
        this.listing = undefined;
      }
    }
  }

  private async analyse(id: number, stream: RtpStream): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    try {
      const result = await client.request("rtp_stream", { stream }, { timeoutMs: 0 });
      this.post({ type: "analysis", id, result });
    } catch (err) {
      this.postError(err, id);
    }
  }

  private async play(id: number, stream: RtpStream): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    try {
      await fs.mkdir(this.audioDir, { recursive: true });
      // A new name each time: the webview would otherwise replay a cached file.
      const file = path.join(this.audioDir, `stream-${++this.audioSeq}.wav`);
      const result = await client.request<Record<string, unknown>>(
        "rtp_audio",
        { stream, dest: file },
        { timeoutMs: 0 },
      );
      const uri = this.panel.webview.asWebviewUri(vscode.Uri.file(file)).toString();
      this.post({ type: "audio", id, uri, ...result });
    } catch (err) {
      this.postError(err, id);
    }
  }

  /** Both directions of call ``call`` (its index) as one stereo WAV, played in the panel. */
  private async playCall(id: number, call: number, streams: CallStream[]): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    try {
      await fs.mkdir(this.audioDir, { recursive: true });
      const file = path.join(this.audioDir, `call-${++this.audioSeq}.wav`);
      const result = await client.request<Record<string, unknown>>(
        "call_audio",
        { streams, dest: file },
        { timeoutMs: 0 },
      );
      const uri = this.panel.webview.asWebviewUri(vscode.Uri.file(file)).toString();
      this.post({ type: "callAudio", id, call, uri, ...result });
    } catch (err) {
      this.postError(err, id);
    }
  }

  private async saveCallAudio(call: number, streams: CallStream[]): Promise<void> {
    const client = this.backend();
    if (!client || !streams.length) {
      return;
    }
    const dest = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(
        exportFileName(this.session.uri.fsPath, `call-${call + 1}`, "wav"),
      ),
      filters: { "WAV audio": ["wav"] },
      title: "Save Call Audio",
    });
    if (!dest) {
      return;
    }
    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Saving the call's audio",
          cancellable: true,
        },
        (_progress, token) =>
          client.request(
            "call_audio",
            { streams, dest: dest.fsPath },
            { timeoutMs: 0, cancellation: token },
          ),
      );
      const reveal = revealLabel();
      if ((await vscode.window.showInformationMessage(`Saved ${dest.fsPath}`, reveal)) === reveal) {
        await revealFile(dest.fsPath);
      }
    } catch (err) {
      if (!(err instanceof RpcError && err.cancelled)) {
        void vscode.window.showErrorMessage(
          `Saving the call's audio failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  private async save(stream: RtpStream, format: "wav" | "raw"): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    const dest = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(audioFileName(this.session.uri.fsPath, stream, format)),
      filters: format === "wav" ? { "WAV audio": ["wav"] } : { "Raw payload": ["raw"] },
      title: format === "wav" ? "Save Audio" : "Save RTP Payload",
    });
    if (!dest) {
      return;
    }
    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Saving audio",
          cancellable: true,
        },
        (_progress, token) =>
          client.request(
            "rtp_audio",
            { stream, dest: dest.fsPath, format },
            {
              timeoutMs: 0,
              cancellation: token,
            },
          ),
      );
      const reveal = revealLabel();
      if ((await vscode.window.showInformationMessage(`Saved ${dest.fsPath}`, reveal)) === reveal) {
        await revealFile(dest.fsPath);
      }
    } catch (err) {
      if (err instanceof RpcError && err.cancelled) {
        return;
      }
      const unsupported =
        err instanceof RpcError && (err.data as { unsupported?: boolean })?.unsupported === true;
      const raw = "Save Raw Payload…";
      const choice = await vscode.window.showErrorMessage(
        `Saving the audio failed: ${err instanceof Error ? err.message : String(err)}`,
        ...(unsupported ? [raw] : []),
      );
      if (choice === raw) {
        await this.save(stream, "raw");
      }
    }
  }

  private postError(err: unknown, id?: number): void {
    const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
    this.post({
      type: "error",
      id,
      message: e.message,
      cancelled: e.cancelled,
      unsupported: (e.data as { unsupported?: boolean } | undefined)?.unsupported === true,
    });
  }

  private dispose(): void {
    VoipPanel.open.delete(this.session.id);
    if (this.listing !== undefined) {
      this.session.backend?.cancel(this.listing);
    }
    void fs.rm(this.audioDir, { recursive: true, force: true });
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
