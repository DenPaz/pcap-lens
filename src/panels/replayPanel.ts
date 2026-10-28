import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import {
  ReplayDestination,
  ReplayOptions,
  normalizeDestinations,
  normalizeOptions,
  normalizePresets,
  rememberDestinations,
  withPreset,
  withoutPreset,
} from "../replayModel";
import { panelHtml, webviewRoot } from "./panelHtml";

/** The destinations used last, per recorded target (globalState). */
const DESTINATIONS_KEY = "pcapViewer.replay.destinations";
/** Speed, loops and scope of the last run (globalState). */
const OPTIONS_KEY = "pcapViewer.replay.options";

/** A recorded target as replay_targets lists it. */
export interface ReplayTarget {
  key: string;
  proto: "tcp" | "udp";
  ip: string;
  port: number;
  connections: number;
  packets: number;
  bytes: number;
  retransmissions: number;
  gaps: number;
  first: number | null;
  last: number | null;
  firstFrame: number;
  protocol: string;
}

/** What a replay request returns (service/replaying.py). */
export interface ReplayResult {
  filter: string;
  stopped: boolean;
  seconds: number;
  loops: number;
  speed: number;
  targets: Record<string, unknown>[];
  log: Record<string, unknown>[];
}

type FromPanel =
  | { type: "ready" }
  | { type: "targets"; scope: "all" | "filter" }
  | ({
      type: "start";
      targets: Record<string, ReplayDestination>;
    } & ReplayOptions)
  | { type: "stop" }
  | { type: "savePreset"; name: string; targets: Record<string, ReplayDestination> }
  | { type: "deletePreset"; name: string }
  | { type: "openSetting" }
  | { type: "goto"; frame: number }
  | { type: "copy"; text: string };

/**
 * Replay to Service for one capture: the recorded targets (server ends), an
 * IP and port for each, and the replay of the operator side to them, with
 * live counts, a log and a summary. The backend reads the capture and owns
 * the sockets (replay.py); see docs/replay-to-service.md.
 */
export class ReplayPanel {
  private static readonly open = new Map<number, ReplayPanel>();
  private static readonly runningEmitter = new vscode.EventEmitter<PcapEditorSession>();
  /** Fires when a replay starts or ends (the session it belongs to). */
  static readonly onDidChangeRunning = ReplayPanel.runningEmitter.event;

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): ReplayPanel {
    const existing = ReplayPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new ReplayPanel(context, session);
    ReplayPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly ReplayPanel[] {
    return [...ReplayPanel.open.values()];
  }

  /** The panel of a session, if open. */
  static of(session: PcapEditorSession): ReplayPanel | undefined {
    return ReplayPanel.open.get(session.id);
  }

  readonly panel: vscode.WebviewPanel;
  /** The last targets and replay result (for tests). */
  targets: ReplayTarget[] | undefined;
  result: ReplayResult | undefined;
  private listing: number | undefined;
  /** Bumped per targets request: an older one's answer is dropped. */
  private listSeq = 0;
  private replaying: number | undefined;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    private readonly context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `Replay to Service · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.replay",
      title,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [root],
        retainContextWhenHidden: true,
      },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "replay.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidDispose(() => this.panel.dispose()),
      session.onDidChangeFilter((filter) => this.post({ type: "filter", filter })),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("pcapViewer.replay")) {
          this.post({ type: "config", ...this.config() });
        }
      }),
    );
  }

  /** A replay is running. */
  get running(): boolean {
    return this.replaying !== undefined;
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private config() {
    const cfg = vscode.workspace.getConfiguration("pcapViewer.replay", this.session.uri);
    return {
      presets: normalizePresets(cfg.get("presets")),
      allowPublic: cfg.get<boolean>("allowPublicTargets", false),
    };
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.post({
          type: "init",
          title: `Replay to Service · ${path.basename(this.session.uri.fsPath)}`,
          filter: this.session.currentFilter,
          destinations: normalizeDestinations(this.context.globalState.get(DESTINATIONS_KEY)),
          options: normalizeOptions(this.context.globalState.get(OPTIONS_KEY)),
          running: this.running,
          ...this.config(),
        });
        return;
      case "targets":
        return this.list(msg.scope);
      case "start":
        return this.start(msg.targets, { speed: msg.speed, loops: msg.loops, scope: msg.scope });
      case "stop":
        return this.stop();
      case "savePreset":
        return this.savePreset(msg.name, msg.targets);
      case "deletePreset":
        return this.deletePreset(msg.name);
      case "openSetting":
        await vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "pcapViewer.replay.allowPublicTargets",
        );
        return;
      case "goto":
        this.session.goTo(msg.frame);
        this.session.reveal();
        return;
      case "copy":
        await vscode.env.clipboard.writeText(msg.text);
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
    }
  }

  private scopeFilter(scope: "all" | "filter"): string {
    return scope === "filter" ? this.session.currentFilter : "";
  }

  private async list(scope: "all" | "filter"): Promise<void> {
    if (this.listing !== undefined) {
      this.session.backend?.cancel(this.listing);
      this.listing = undefined;
    }
    const seq = ++this.listSeq;
    this.post({ type: "loading", text: "Reading the capture…" });
    await this.session.whenIndexed();
    if (seq !== this.listSeq) {
      return;
    }
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        where: "targets",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    const filter = this.scopeFilter(scope);
    this.post({ type: "loading", text: "Finding the recorded targets…" });
    const pending = client.send<{ targets: ReplayTarget[]; duration: number; filter: string }>(
      "replay_targets",
      { filter },
      { timeoutMs: 0 },
    );
    this.listing = pending.id;
    try {
      const result = await pending.promise;
      if (seq !== this.listSeq) {
        return;
      }
      this.targets = result.targets;
      this.post({ type: "targets", ...result });
    } catch (err) {
      if (seq === this.listSeq) {
        this.postError("targets", err);
      }
    } finally {
      if (this.listing === pending.id) {
        this.listing = undefined;
      }
    }
  }

  /** Replay the operator side to `targets` (the panel's Start; also used by the smoke test). */
  async start(targets: Record<string, ReplayDestination>, options: ReplayOptions): Promise<void> {
    const client = this.session.backend;
    if (this.running) {
      return;
    }
    if (!client?.running) {
      this.post({
        type: "error",
        where: "replay",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    const opts = normalizeOptions(options);
    const mapping = normalizeDestinations(targets);
    await this.context.globalState.update(OPTIONS_KEY, opts);
    await this.context.globalState.update(
      DESTINATIONS_KEY,
      rememberDestinations(this.context.globalState.get(DESTINATIONS_KEY), mapping),
    );
    const pending = client.send<ReplayResult>(
      "replay",
      {
        filter: this.scopeFilter(opts.scope),
        targets: mapping,
        speed: opts.speed,
        loops: opts.loops,
        allowPublic: this.config().allowPublic,
      },
      { timeoutMs: 0, onProgress: (p) => this.post({ type: "progress", progress: p }) },
    );
    this.replaying = pending.id;
    ReplayPanel.runningEmitter.fire(this.session);
    this.post({ type: "started" });
    try {
      this.result = await pending.promise;
      this.post({ type: "done", result: this.result });
    } catch (err) {
      this.postError("replay", err);
    } finally {
      this.replaying = undefined;
      ReplayPanel.runningEmitter.fire(this.session);
    }
  }

  /** End the running replay cleanly (its summary still comes). */
  async stop(): Promise<void> {
    const client = this.session.backend;
    if (this.replaying === undefined || !client?.running) {
      return;
    }
    try {
      await client.request("replay_stop", {});
    } catch {
      if (this.replaying !== undefined) {
        client.cancel(this.replaying);
      }
    }
  }

  private postError(where: "targets" | "replay", err: unknown): void {
    const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
    const data = (e.data ?? {}) as { target?: unknown };
    this.post({
      type: "error",
      where,
      message: e.message,
      cancelled: e.cancelled,
      target: typeof data.target === "string" ? data.target : undefined,
      // (resolve_target's refusal of a public destination: the setting allows it.)
      publicTarget: /must be allowed explicitly/.test(e.message),
    });
  }

  private async savePreset(
    current: string,
    targets: Record<string, ReplayDestination>,
  ): Promise<void> {
    const mapping = normalizeDestinations(targets);
    if (!Object.keys(mapping).length) {
      return;
    }
    const cfg = vscode.workspace.getConfiguration("pcapViewer.replay", this.session.uri);
    const presets = normalizePresets(cfg.get("presets"));
    const name = await vscode.window.showInputBox({
      title: "Save Replay Preset",
      prompt: "A name for these destinations (an existing name is replaced)",
      value: current,
      validateInput: (v) => (v.trim() ? undefined : "Enter a name"),
    });
    if (!name?.trim()) {
      return;
    }
    const preset = { name: name.trim(), targets: mapping };
    await cfg.update("presets", withPreset(presets, preset), vscode.ConfigurationTarget.Global);
    this.post({ type: "config", ...this.config(), selected: preset.name });
  }

  private async deletePreset(name: string): Promise<void> {
    const cfg = vscode.workspace.getConfiguration("pcapViewer.replay", this.session.uri);
    const presets = normalizePresets(cfg.get("presets"));
    if (!presets.some((p) => p.name === name)) {
      return;
    }
    const remove = "Delete";
    const choice = await vscode.window.showWarningMessage(
      `Delete the replay preset "${name}"?`,
      { modal: true },
      remove,
    );
    if (choice === remove) {
      await cfg.update("presets", withoutPreset(presets, name), vscode.ConfigurationTarget.Global);
      this.post({ type: "config", ...this.config(), selected: "" });
    }
  }

  private dispose(): void {
    ReplayPanel.open.delete(this.session.id);
    const client = this.session.backend;
    if (this.listing !== undefined) {
      client?.cancel(this.listing);
    }
    if (this.replaying !== undefined) {
      client?.cancel(this.replaying); // (closes the connections)
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
