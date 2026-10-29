import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, Progress, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import {
  MAX_FILES,
  MAX_SAVED_LOG,
  ReplayDestination,
  ReplayLogLine,
  ReplayOptions,
  ReplayRun,
  ReplaySetup,
  ReplaySourceResult,
  ReplayTargetResult,
  isCaptureFileName,
  normalizeDestinations,
  normalizeOptions,
  normalizePresets,
  openPosition,
  parseSetup,
  rememberDestinations,
  resultsToJson,
  resultsToText,
  setupToJson,
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
  /** A packet of the open capture; null when only other captures record the target. */
  firstFrame: number | null;
  /** The capture that records it, when the open one doesn't. */
  recordedIn?: string;
  protocol: string;
}

/**
 * The captures a replay reads: other files, with the open one (unless
 * `capture` is false) at position `openAt` among them (default 0: first).
 */
export interface ReplaySources {
  capture: boolean;
  files: string[];
  openAt?: number;
}

/** What a replay request returns (service/replaying.py). */
export interface ReplayResult {
  filter: string;
  stopped: boolean;
  seconds: number;
  loops: number;
  speed: number;
  targets: Record<string, unknown>[];
  sources?: Record<string, unknown>[];
  log: Record<string, unknown>[];
}

type FromPanel =
  | { type: "ready" }
  | ({ type: "targets"; scope: "all" | "filter" } & ReplaySources)
  | ({
      type: "start";
      targets: Record<string, ReplayDestination>;
    } & ReplayOptions &
      ReplaySources)
  | { type: "addCaptures" }
  | { type: "addFolder" }
  | { type: "saveSetup"; setup: ReplaySetup }
  | { type: "saveResults" }
  | { type: "loadSetup" }
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
  /** The last finished replay, for Save Results…. */
  lastRun: ReplayRun | undefined;
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
    session.replayControl = {
      reveal: () => this.panel.reveal(undefined, false),
      stop: () => void this.stop(),
    };
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
        return this.list(msg.scope, msg);
      case "start":
        return this.start(msg.targets, msg, msg);
      case "addCaptures":
        return this.addCaptures();
      case "addFolder":
        return this.addFolder();
      case "saveSetup":
        return this.saveSetup(msg.setup);
      case "saveResults":
        return this.saveResults();
      case "loadSetup":
        return this.loadSetup();
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

  private async list(scope: "all" | "filter", sources: ReplaySources): Promise<void> {
    if (this.listing !== undefined) {
      this.session.backend?.cancel(this.listing);
      this.listing = undefined;
    }
    const seq = ++this.listSeq;
    const files = checkedFiles(sources.files);
    if (!sources.capture && !files.length) {
      this.post({ type: "targets", targets: [], sources: [], duration: 0, span: 0, filter: "" });
      return;
    }
    this.post({ type: "loading", text: "Reading the capture…" });
    if (sources.capture) {
      await this.session.whenIndexed();
    }
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
    this.post({
      type: "loading",
      text: files.length ? "Reading the captures…" : "Finding the recorded targets…",
    });
    const pending = client.send<{ targets: ReplayTarget[]; duration: number; filter: string }>(
      "replay_targets",
      {
        filter,
        capture: sources.capture,
        files,
        openAt: openPosition(sources.openAt, files.length),
      },
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

  /**
   * Replay the operator side to `targets` (the panel's Start; also used by
   * the smoke test): `sources.files` with the open capture at `sources.openAt`
   * (first by default), as `options` say.
   */
  async start(
    targets: Record<string, ReplayDestination>,
    options: Partial<ReplayOptions>,
    sources: ReplaySources = { capture: true, files: [] },
  ): Promise<void> {
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
    const files = checkedFiles(sources.files);
    await this.context.globalState.update(OPTIONS_KEY, opts);
    await this.context.globalState.update(
      DESTINATIONS_KEY,
      rememberDestinations(this.context.globalState.get(DESTINATIONS_KEY), mapping),
    );
    const started = Date.now();
    // The whole log, for Save Results… (the panel keeps the last lines only).
    const log: ReplayLogLine[] = [];
    let logOmitted = 0;
    const keepLog = (lines: unknown) => {
      for (const line of Array.isArray(lines) ? (lines as ReplayLogLine[]) : []) {
        if (log.length < MAX_SAVED_LOG) {
          log.push(line);
        } else {
          logOmitted += 1;
        }
      }
    };
    const status = {
      targets: Object.keys(mapping).length,
      sent: 0,
      received: 0,
      seconds: 0,
      loop: 1,
      loops: opts.loops,
    };
    const onProgress = (p: Progress) => {
      this.post({ type: "progress", progress: p });
      keepLog((p as { log?: unknown }).log);
      const r = p as Progress & { loop?: number; sent?: number; received?: number };
      status.sent = r.sent ?? status.sent;
      status.received = r.received ?? status.received;
      status.loop = r.loop ?? status.loop;
      status.seconds = (Date.now() - started) / 1000;
      this.session.showReplay({ ...status });
    };
    const pending = client.send<ReplayResult>(
      "replay",
      {
        filter: this.scopeFilter(opts.scope),
        capture: sources.capture,
        files,
        openAt: openPosition(sources.openAt, files.length),
        order: opts.order,
        targets: mapping,
        speed: opts.speed,
        loops: opts.loops,
        jitter: opts.jitter,
        loss: opts.loss,
        allowPublic: this.config().allowPublic,
      },
      { timeoutMs: 0, onProgress },
    );
    this.replaying = pending.id;
    ReplayPanel.runningEmitter.fire(this.session);
    this.post({ type: "started" });
    this.session.showReplay({ ...status });
    try {
      this.result = await pending.promise;
      keepLog(this.result.log);
      this.lastRun = {
        capture: this.session.uri.fsPath,
        started: new Date(started).toISOString(),
        ended: new Date().toISOString(),
        options: opts,
        filter: this.scopeFilter(opts.scope),
        files,
        includeOpen: sources.capture,
        openAt: openPosition(sources.openAt, files.length),
        stopped: this.result.stopped,
        seconds: this.result.seconds,
        loops: this.result.loops,
        targets: this.result.targets as unknown as ReplayTargetResult[],
        sources: (this.result.sources ?? []) as unknown as ReplaySourceResult[],
        log,
        logOmitted,
      };
      this.post({ type: "done", result: this.result });
    } catch (err) {
      this.postError("replay", err);
    } finally {
      this.replaying = undefined;
      this.session.showReplay(null);
      ReplayPanel.runningEmitter.fire(this.session);
    }
  }

  /** End the running replay cleanly (its summary still comes). */
  async stop(): Promise<void> {
    const client = this.session.backend;
    if (this.replaying === undefined || !client?.running) {
      return;
    }
    let stopped = false;
    try {
      ({ stopped } = await client.request<{ stopped: boolean }>("replay_stop", {}));
    } catch {
      // (cancelled below)
    }
    // Still starting (reading the capture, resolving the destinations): nothing
    // ran yet for replay_stop to end, so the request itself is cancelled.
    if (!stopped && this.replaying !== undefined) {
      client.cancel(this.replaying);
    }
  }

  /** The folder new captures and setups are picked from: the capture's. */
  private get folder(): vscode.Uri {
    return vscode.Uri.file(path.dirname(this.session.uri.fsPath));
  }

  private async addCaptures(): Promise<void> {
    const picked = await vscode.window.showOpenDialog({
      title: "Add Captures to the Replay",
      canSelectMany: true,
      defaultUri: this.folder,
      openLabel: "Add",
      filters: {
        Captures: ["pcap", "pcapng", "cap", "ntar", "gz", "zst", "lz4", "snoop", "erf"],
        "All files": ["*"],
      },
    });
    if (picked?.length) {
      this.post({ type: "filesAdded", files: picked.map((u) => u.fsPath), enabled: true });
    }
  }

  /** Every capture file in a folder (not its subfolders), unchecked: pick the ones to play. */
  private async addFolder(): Promise<void> {
    const picked = await vscode.window.showOpenDialog({
      title: "Add a Folder of Captures to the Replay",
      canSelectFiles: false,
      canSelectFolders: true,
      defaultUri: this.folder,
      openLabel: "Add Folder",
    });
    const dir = picked?.[0];
    if (!dir) {
      return;
    }
    let entries: [string, vscode.FileType][];
    try {
      entries = await vscode.workspace.fs.readDirectory(dir);
    } catch (err) {
      void vscode.window.showWarningMessage(`Can't read ${dir.fsPath}: ${String(err)}`);
      return;
    }
    const files = entries
      .filter(([name, kind]) => kind === vscode.FileType.File && isCaptureFileName(name))
      .map(([name]) => vscode.Uri.joinPath(dir, name).fsPath)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    if (!files.length) {
      void vscode.window.showInformationMessage(`No capture files in ${dir.fsPath}.`);
      return;
    }
    this.post({ type: "filesAdded", files: files.slice(0, MAX_FILES), enabled: false });
  }

  private async saveSetup(setup: ReplaySetup): Promise<void> {
    const uri = await vscode.window.showSaveDialog({
      title: "Save Replay Setup",
      defaultUri: vscode.Uri.joinPath(this.folder, "replay-setup.json"),
      filters: { "Replay setup": ["json"] },
    });
    if (!uri) {
      return;
    }
    const text = setupToJson(setup, path.dirname(uri.fsPath));
    await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(text));
    this.post({ type: "setupSaved", name: path.basename(uri.fsPath) });
  }

  /**
   * Save the last replay's summary, counts and whole log: text, or JSON when
   * the name ends in .json (`dest` skips the dialog: the smoke test).
   */
  async saveResults(dest?: vscode.Uri): Promise<void> {
    const run = this.lastRun;
    if (!run) {
      return;
    }
    const stamp = run.started.replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
    const stem = path.basename(run.capture).replace(/\.[^.]+$/, "");
    const uri =
      dest ??
      (await vscode.window.showSaveDialog({
        title: "Save Replay Results",
        defaultUri: vscode.Uri.joinPath(this.folder, `replay-${stem}-${stamp}.txt`),
        filters: { Text: ["txt"], JSON: ["json"] },
      }));
    if (!uri) {
      return;
    }
    const text = uri.fsPath.toLowerCase().endsWith(".json")
      ? resultsToJson(run)
      : resultsToText(run);
    await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(text));
    this.post({ type: "resultsSaved", name: path.basename(uri.fsPath) });
  }

  private async loadSetup(): Promise<void> {
    const picked = await vscode.window.showOpenDialog({
      title: "Load Replay Setup",
      defaultUri: this.folder,
      openLabel: "Load",
      filters: { "Replay setup": ["json"], "All files": ["*"] },
    });
    const uri = picked?.[0];
    if (!uri) {
      return;
    }
    let text: string;
    try {
      text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
    } catch (err) {
      void vscode.window.showWarningMessage(`Can't read ${uri.fsPath}: ${String(err)}`);
      return;
    }
    const parsed = parseSetup(text, path.dirname(uri.fsPath));
    if ("error" in parsed) {
      void vscode.window.showWarningMessage(`${path.basename(uri.fsPath)} is ${parsed.error}.`);
      return;
    }
    const missing: string[] = [];
    for (const c of parsed.setup.captures) {
      try {
        await vscode.workspace.fs.stat(vscode.Uri.file(c.path));
      } catch {
        missing.push(c.path);
      }
    }
    this.post({
      type: "setup",
      name: path.basename(uri.fsPath),
      setup: parsed.setup,
      problems: parsed.problems,
      missing,
    });
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
    this.session.replayControl = undefined;
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

/** The file paths a message names, checked (strings, at most MAX_FILES, no repeats). */
function checkedFiles(files: unknown): string[] {
  if (!Array.isArray(files)) {
    return [];
  }
  const out: string[] = [];
  for (const f of files) {
    if (typeof f === "string" && f && !out.includes(f) && out.length < MAX_FILES) {
      out.push(f);
    }
  }
  return out;
}
