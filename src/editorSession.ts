/** One capture editor panel: its backend, its webview and the requests between them. */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { BackendClient, ErrorCodes, RpcError, findPython } from "./backendClient";
import {
  CAPTURE_OPENED,
  FILTER_APPLIED,
  offerSetupHelp,
  openCopy,
  setEnvironmentContext,
} from "./commands/setup";
import { copyName, isOnDisk } from "./remote";
import { rememberRecentCapture } from "./commands/recent";
import {
  Settings,
  getSetting,
  readColoringStyle,
  readQuickDetail,
  readSettings,
  updateSetting,
} from "./config";
import type {
  AnomalyRequest,
  ExplainOutcome,
  ExplainSink,
  FilterAssistant,
  SuggestOutcome,
} from "./ai";
import type { ToolConsent } from "./aiTools";
import {
  CaptureEvent,
  ColoringResult,
  FilterEvent,
  HostToWebview,
  OpenResult,
  ViewCounts,
  ViewerCommand,
  WEBVIEW_RPC_METHODS,
  WebviewToHost,
} from "./messages";
import { saveFilterInteractive, showSavedFilters } from "./commands/savedFilters";
import { addFilterButtonInteractive, editFilterButton } from "./commands/filterButtons";
import { FOLLOW_LABELS, FollowPanel } from "./panels/followPanel";
import { rotatedSiblings } from "./rotation";
import { MenuCommand, buildCommandMenu } from "./commandMenu";
import {
  ColoringRule,
  ColoringStyle,
  ColumnLayout,
  ColumnSetting,
  DEFAULT_NAME_RESOLUTION,
  FilterButton,
  MAX_COLORING_RULES,
  NameResolution,
  QuickDetail,
  SavedFilter,
  TimeFormat,
  addColumn,
  colorizeConversation,
  luaLabel,
  nameResolutionLabel,
  normalizeColumns,
  pushHistory,
} from "./settingsModel";
import type { PcapDocument } from "./pcapDocument";
import type { PrefOverrides } from "./prefsModel";

const HISTORY_KEY = "pcapViewer.filterHistory";
/**
 * How long the backend may take to find tshark and run `tshark --version`.
 * Usually well under a second, but a first run after installing or updating
 * Wireshark can take much longer (macOS checks the app; seen above 30 s).
 */
const INITIALIZE_TIMEOUT_MS = 120_000;
/** After this long, the viewer says tshark's first start can be slow. */
const SLOW_START_MS = 5_000;
/** Coloring problems already shown in a notification (each is reported once per window). */
const reportedColoringErrors = new Set<string>();
/** The button that opens a file of BER records as packets (pcapViewer.openBerRecords). */
export const OPEN_AS_PACKETS = "Open Records as Packets…";

/** The configured coloring rules to apply ([] when coloring is off). */
function configuredRules(settings: Settings): ColoringRule[] {
  return settings.colorize ? settings.coloringRules : [];
}

/** Rules as the backend takes them (open's `coloring` and set_coloring: the same list, so saved colors match). */
function coloringPayload(
  rules: ColoringRule[],
): { filter: string; foreground: string; background: string }[] {
  return rules.map((r) => ({
    filter: r.filter,
    foreground: r.foreground,
    background: r.background,
  }));
}

let menuCache: MenuCommand[] | undefined;

/** The ☰ menu's commands, built once from the extension's package.json. */
function commandMenu(context: vscode.ExtensionContext): MenuCommand[] {
  menuCache ??= buildCommandMenu(context.extension.packageJSON);
  return menuCache;
}

let nextSessionId = 1;

/** Where saved packet-list indexes live (the extension's own storage). */
export function indexCacheDir(context: vscode.ExtensionContext): string {
  return path.join(context.globalStorageUri.fsPath, "index-cache");
}

export class PcapEditorSession {
  /** Unique per editor panel (keys the statistics panels). */
  readonly id = nextSessionId++;
  /** Frame currently selected (focused) in the packet list, if any. */
  selectedFrame: number | null = null;
  /** Every selected frame when several are (Shift/Ctrl+click), else empty. */
  selectedFrames: number[] = [];
  /** Number of marked packets (the marks themselves live in the backend). */
  markedCount = 0;
  /** TLS key log file this capture was last loaded with ("" = none). */
  keyLogFile = "";
  /** Name resolution this capture was last loaded with. */
  names: NameResolution = DEFAULT_NAME_RESOLUTION;
  /** The preference overrides of the latest load (incl. the TLS key log): see readSettings. */
  prefs: PrefOverrides = {};
  /** The Lua scripts of the latest load (settings, or this capture's choice). */
  lua: string[] = [];
  private keyLogWatcher?: vscode.Disposable;
  /** Merging this rotated capture's pieces was offered (once per editor). */
  private mergeOffered = false;
  private readonly disposeEmitter = new vscode.EventEmitter<void>();
  /** Fires when the editor closes (auxiliary panels close with it). */
  readonly onDidDispose = this.disposeEmitter.event;
  private readonly activateEmitter = new vscode.EventEmitter<void>();
  /** Fires when one of this capture's auxiliary panels gains focus. */
  readonly onDidActivate = this.activateEmitter.event;
  private readonly filterEmitter = new vscode.EventEmitter<string>();
  /** Fires with the new display filter when the viewer applies one (panels that follow the view). */
  readonly onDidChangeFilter = this.filterEmitter.event;
  private readonly captureEmitter = new vscode.EventEmitter<void>();
  /** Fires when a live capture starts or stops. */
  readonly onDidChangeCapture = this.captureEmitter.event;
  /** A live capture is writing this capture (capture_start). */
  capturing = false;
  /** Settings changed while capturing: reload once the capture is indexed. */
  private reloadWhenCaptured = false;
  /** Called when the index pass ends (see whenIndexed). */
  private indexedWaiters: (() => void)[] = [];
  private client?: BackendClient;
  private info?: OpenResult;
  private filter = "";
  private loading?: { id: number; client: BackendClient };
  /** webview request id -> backend request id (for cancellation). */
  private readonly inflight = new Map<number, number>();
  private readonly disposables: vscode.Disposable[] = [];
  private disposed = false;
  private loadSeq = 0;
  /** When the latest load started (Date.now()), for the log's timings. */
  private loadStarted = 0;
  private coloring?: { id: number; client: BackendClient };
  /** A streaming open is still indexing (coloring rules evaluated by the index pass). */
  private indexing = false;
  /** The coloring rules changed while indexing: run a coloring pass when it's done. */
  private coloringStale = false;
  /** Colorize Conversation's rules (this editor only, ahead of the configured ones). */
  private temporaryRules: ColoringRule[] = [];
  /** In-flight "Ask AI" requests from the webview, by webview request id. */
  private readonly aiRequests = new Map<number, vscode.CancellationTokenSource>();
  private readonly ready: Promise<void>;

  readonly uri: vscode.Uri;

  constructor(
    private readonly context: vscode.ExtensionContext,
    readonly document: PcapDocument,
    readonly panel: vscode.WebviewPanel,
    private readonly log: vscode.LogOutputChannel,
    private readonly assistant: FilterAssistant,
    /** Change packet comments (frame → text, "" deletes) as one undoable edit. */
    readonly editComments: (changes: Map<number, string>, label: string) => void,
  ) {
    this.uri = document.uri;
    const webviewRoot = vscode.Uri.joinPath(context.extensionUri, "src", "webview");
    panel.webview.options = { enableScripts: true, localResourceRoots: [webviewRoot] };
    panel.webview.html = this.renderHtml(webviewRoot);
    let markReady: () => void = () => undefined;
    this.ready = new Promise((resolve) => (markReady = resolve));
    this.disposables.push(
      panel.webview.onDidReceiveMessage((msg: WebviewToHost) => {
        if (msg.type === "ready") {
          markReady();
          // (Before the capture loads: Reload or Show Log help when it fails.)
          this.post({ type: "commands", commands: this.menuCommands });
          this.setColoringStyle(readColoringStyle(this.uri));
          this.setFilterButtons(readSettings().filterButtons);
        }
        void this.onMessage(msg);
      }),
    );
    this.disposables.push(assistant.onDidChangeAvailability(() => void this.postAiAvailability()));
    this.disposables.push(document.onDidChangeEdits((e) => void this.pushComments(e.reload)));
    void this.ready.then(() => this.load());
  }

  get openInfo(): OpenResult | undefined {
    return this.info;
  }

  /**
   * packet_detail's parameters for `frame`, as the viewer asks: two passes
   * (pcapViewer.twoPassDetail) for a small capture that is completely indexed.
   */
  detailParams(frame: number): { number: number; twoPass?: boolean } {
    const limit = readQuickDetail(this.uri).twoPass ?? 0;
    const small = !!this.info && !this.indexing && this.info.frames <= limit;
    return small ? { number: frame, twoPass: true } : { number: frame };
  }

  /** Send the document's comment edits to this editor's backend and refresh the viewer. */
  private async pushComments(reload: boolean): Promise<void> {
    const client = this.client;
    if (!client?.running || !this.info || this.disposed) {
      return; // (the next load pushes them)
    }
    try {
      await client.request("set_comments", { edits: this.document.editsParam(), reload });
    } catch (err) {
      this.log.warn(`${this.uri.fsPath}: packet comments not updated: ${String(err)}`);
    }
    if (this.client === client && !this.disposed) {
      this.post({ type: "commentsChanged" });
    }
  }

  get backend(): BackendClient | undefined {
    return this.client;
  }

  get currentFilter(): string {
    return this.filter;
  }

  /**
   * (Re)start the backend and index the file. `reason` goes to the log
   * ("open", "Reload", "settings changed"…), with the time each step took.
   */
  async load(reason = "open"): Promise<void> {
    if (this.capturing) {
      // Restarting would end the capture: apply the settings once it's done.
      this.reloadWhenCaptured = true;
      return;
    }
    if (!isOnDisk(this.uri)) {
      this.notOnDisk();
      return;
    }
    const seq = ++this.loadSeq;
    const name = path.basename(this.uri.fsPath);
    this.log.info(`${name}: loading (${reason})`);
    const settings = readSettings(this.uri);
    this.watchKeyLog(settings.tlsKeyLogFile);
    this.names = settings.nameResolution;
    this.prefs = settings.prefs;
    this.lua = settings.luaScripts;
    await this.stopBackend();
    if (this.disposed || seq !== this.loadSeq) {
      return;
    }
    this.post({ type: "loading", message: "Starting backend…" });

    const py = findPython(settings.pythonPath || undefined);
    if ("error" in py) {
      this.fail(py.error, "pythonPath");
      return;
    }
    const client = new BackendClient({
      python: py.python,
      backendDir: vscode.Uri.joinPath(this.context.extensionUri, "backend").fsPath,
      logger: {
        info: (m) => this.log.info(m),
        warn: (m) => this.log.warn(m),
        error: (m) => this.log.error(m),
      },
      maxCachedFrames: settings.maxCachedFrames,
      defaultTimeoutMs: settings.requestTimeoutMs,
    });
    this.client = client;
    client.onExit(({ expected }) => {
      if (!expected && this.client === client && !this.disposed) {
        this.client = undefined;
        this.post({
          type: "error",
          message: "The PCAP backend stopped unexpectedly. See the PCAP Lens log for details.",
          canReload: true,
        });
      }
    });

    const started = Date.now();
    this.loadStarted = started;
    const seconds = (from: number) => `${((Date.now() - from) / 1000).toFixed(1)} s`;
    let initialized = false;
    // tshark's first run can be slow (on macOS the system checks Wireshark.app
    // the first time it runs after an install or update): say so meanwhile.
    const slowStart = setTimeout(() => {
      if (seq === this.loadSeq && !this.disposed) {
        this.post({
          type: "loading",
          message:
            "Starting tshark… Its first run after installing or updating Wireshark can take a minute.",
        });
      }
    }, SLOW_START_MS);
    try {
      client.start();
      const init = await client
        .request<{ version: string; tsharkPath: string }>(
          "initialize",
          { tsharkPath: settings.tsharkPath || undefined },
          { timeoutMs: INITIALIZE_TIMEOUT_MS },
        )
        .finally(() => clearTimeout(slowStart));
      initialized = true;
      this.log.info(
        `using ${init.version} at ${init.tsharkPath} (python ${py.version}; ready after ${seconds(started)})`,
      );
      setEnvironmentContext(true, true);
      this.post({ type: "loading", message: "Indexing packets…" });
      // A streaming open's "index" events can arrive before the open response:
      // keep them until the viewer has its init, then replay them.
      const early: Record<string, unknown>[] = [];
      let onIndex = (p: Record<string, unknown>) => void early.push(p);
      const stopIndexEvents = client.onNotification("index", (p) => onIndex(p));
      // The file's packet comments are read after the open: show them once known.
      client.onNotification("comments", (p) => {
        if (this.client === client && !this.disposed) {
          if (typeof p.error === "string") {
            this.log.warn(`${this.uri.fsPath}: ${p.error}`);
          }
          this.post({ type: "commentsChanged" });
        }
      });
      // Streaming filters report their matches as they come.
      client.onNotification("filter", (p) => {
        if (this.client === client && !this.disposed) {
          this.post({ type: "filterEvent", ...(p as unknown as FilterEvent) });
        }
      });
      client.onNotification("capture", (p) =>
        this.onCaptureEvent(client, p as unknown as CaptureEvent),
      );
      const opening = Date.now();
      const info = await this.openFile(client, settings);
      if (seq !== this.loadSeq || this.disposed) {
        stopIndexEvents();
        return;
      }
      this.info = info;
      if (info.indexing && !info.capture) {
        this.log.info(
          `${name}: first ${info.frames.toLocaleString("en-US")} packets shown after ${seconds(opening)}; indexing the rest`,
        );
      } else if (!info.fromCache && !info.capture) {
        this.log.info(
          `${name}: ${info.frames.toLocaleString("en-US")} packets indexed in ${seconds(opening)}`,
        );
      }
      if (info.capture?.running) {
        this.capturing = true;
        this.captureEmitter.fire();
      }
      if (info.fromCache) {
        this.log.info(`${this.uri.fsPath}: opened from the saved index (no index pass)`);
      }
      this.reportWarnings([...settings.luaWarnings, ...info.warnings]);
      this.indexing = !!info.indexing;
      this.coloringStale = false;
      void vscode.commands.executeCommand("setContext", CAPTURE_OPENED, true);
      if (!this.document.temporary) {
        rememberRecentCapture(this.uri, info);
      }
      this.post({
        type: "init",
        info,
        columns: settings.columns,
        layout: settings.columnLayout,
        timeFormat: settings.timeFormat,
        quickDetail: settings.quickDetail,
        filter: this.filter,
        history: this.history(),
        savedFilters: settings.savedFilters,
        elapsedMs: Date.now() - started,
        names: nameResolutionLabel(settings.nameResolution),
        lua: luaLabel(settings.luaScripts, settings.luaAvailable, settings.luaChosen),
      });
      if (info.coloring) {
        // Colors come with the rows (or were saved with the index).
        this.showColoring(
          { colored: 0, errors: {}, ...info.coloring },
          this.coloringRules(settings),
        );
      }
      if (info.indexing) {
        const known = info.warnings.length;
        onIndex = (p) => {
          if (this.onIndexEvent(client, p, known)) {
            stopIndexEvents();
          }
        };
        early.splice(0).forEach(onIndex);
      } else {
        stopIndexEvents();
        if (!info.coloring) {
          void this.applyColoring();
        }
      }
      if (this.document.editCount) {
        void this.pushComments(false); // edits made in another editor, or restored
      }
      void this.postAiAvailability();
      if (!this.document.temporary) {
        void this.offerMerge();
      }
    } catch (err) {
      clearTimeout(slowStart); // (also when the backend didn't even start)
      if (seq !== this.loadSeq || this.disposed) {
        return;
      }
      if (err instanceof RpcError && err.cancelled) {
        this.post({ type: "error", message: "Loading was cancelled.", canReload: true });
        await this.stopBackend();
        return;
      }
      if (!initialized) {
        // (Don't leave a backend that never answered running until the next Reload.)
        await this.stopBackend();
      }
      if (err instanceof RpcError && err.code === ErrorCodes.UnsupportedFormat) {
        this.unsupportedFormat(err);
        return;
      }
      const setting =
        err instanceof RpcError && err.code === ErrorCodes.TsharkNotFound
          ? "tsharkPath"
          : undefined;
      this.fail(describeError(err), setting);
    }
  }

  /**
   * Browsers keep appending to their key log: when it changes, offer to reload
   * so newer TLS sessions are decrypted too (at most one question at a time).
   */
  private watchKeyLog(file: string): void {
    this.keyLogWatcher?.dispose();
    this.keyLogWatcher = undefined;
    this.keyLogFile = file;
    if (!file) {
      return;
    }
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(path.dirname(file)), path.basename(file)),
    );
    let timer: NodeJS.Timeout | undefined;
    let asking = false;
    const changed = () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        if (asking || this.disposed || this.keyLogFile !== file) {
          return;
        }
        asking = true;
        const choice = await vscode.window.showInformationMessage(
          `PCAP Lens: the TLS key log ${path.basename(file)} changed. Reload ${path.basename(this.uri.fsPath)} to decrypt with the new keys?`,
          "Reload",
        );
        asking = false;
        if (choice === "Reload" && !this.disposed) {
          void this.load("TLS key log changed");
        }
      }, 1000); // browsers write one key at a time
    };
    watcher.onDidChange(changed);
    watcher.onDidCreate(changed);
    this.keyLogWatcher = {
      dispose: () => {
        clearTimeout(timer);
        watcher.dispose();
      },
    };
  }

  /** A piece of a rotated capture (tcpdump -C, dumpcap ring buffer): offer to merge all of them. */
  private async offerMerge(): Promise<void> {
    const never = "pcapViewer.mergeOffer.never";
    if (this.mergeOffered || this.context.globalState.get<boolean>(never)) {
      return;
    }
    this.mergeOffered = true;
    const pieces = await rotatedSiblings(this.uri.fsPath);
    if (pieces.length < 2 || this.disposed) {
      return;
    }
    const merge = "Merge…";
    const stop = "Don't Ask Again";
    const choice = await vscode.window.showInformationMessage(
      `PCAP Lens: ${path.basename(this.uri.fsPath)} is one of ${pieces.length} pieces of a rotated capture. Merge them into one capture?`,
      merge,
      stop,
    );
    if (choice === merge) {
      await vscode.commands.executeCommand("pcapViewer.mergeCaptures", pieces);
    } else if (choice === stop) {
      await this.context.globalState.update(never, true);
    }
  }

  private reportWarnings(warnings: string[]): void {
    for (const w of warnings) {
      this.log.warn(`${this.uri.fsPath}: ${w}`);
    }
    // Lua load errors are errors, not warnings: say so and point at the log.
    const luaErrors = warnings.filter((w) => w.startsWith("Lua:"));
    const others = warnings.filter((w) => !w.startsWith("Lua:"));
    if (luaErrors.length) {
      const first = luaErrors[0].split("\n")[0].replace(/^Lua: /, "");
      void vscode.window
        .showErrorMessage(
          `PCAP Lens: Lua dissector error: ${first}${luaErrors.length > 1 ? ` (+${luaErrors.length - 1} more)` : ""}`,
          "Show Log",
        )
        .then((choice) => choice && this.log.show());
    }
    if (others.length) {
      void vscode.window
        .showWarningMessage(
          `PCAP Lens: ${others[0]}${others.length > 1 ? ` (+${others.length - 1} more)` : ""}`,
          "Show Log",
        )
        .then((choice) => {
          if (choice) {
            this.log.show();
          }
        });
    }
  }

  /**
   * An "index" notification of a streaming open: progress goes to the viewer;
   * the end brings the final info, then coloring starts. Returns true at the end.
   */
  private onIndexEvent(
    client: BackendClient,
    p: Record<string, unknown>,
    knownWarnings: number,
  ): boolean {
    if (this.client !== client || this.disposed) {
      return true;
    }
    if (p.event === "progress") {
      this.post({
        type: "indexProgress",
        frames: Number(p.frames) || 0,
        fraction: typeof p.fraction === "number" ? p.fraction : null,
        view: p.view as ViewCounts | undefined,
        phase: p.phase === "catching-up" ? "catching-up" : "indexing",
        resumedAt: typeof p.resumedAt === "number" ? p.resumedAt : undefined,
        restarted: p.restarted === true ? true : undefined,
      });
      return false;
    }
    const info = p.info as OpenResult | undefined;
    if (info) {
      this.info = info;
      this.reportWarnings(info.warnings.slice(knownWarnings));
    }
    const error = p.event === "failed" ? String(p.message ?? "indexing failed") : undefined;
    if (error) {
      this.log.warn(`${this.uri.fsPath}: indexing stopped: ${error}`);
    } else if (info && !info.capture) {
      const took = ((Date.now() - this.loadStarted) / 1000).toFixed(1);
      this.log.info(
        `${path.basename(this.uri.fsPath)}: ${info.frames.toLocaleString("en-US")} packets indexed, ${took} s after loading started`,
      );
    }
    this.indexing = false;
    this.indexedWaiters.splice(0).forEach((resolve) => resolve());
    if (this.capturing) {
      this.capturing = false; // (its "stopped" event normally came first)
      this.captureEmitter.fire();
    }
    if (this.reloadWhenCaptured) {
      this.reloadWhenCaptured = false;
      setTimeout(() => void this.load("settings changed during the capture"), 0);
    }
    if (this.info) {
      if (!this.document.temporary) {
        rememberRecentCapture(this.uri, this.info); // the final packet count
      }
      this.post({
        type: "indexDone",
        info: this.info,
        error,
        view: p.view as ViewCounts | undefined,
      });
      const coloring = p.coloring as ColoringResult | undefined;
      if (coloring && !this.coloringStale) {
        this.showColoring(coloring, this.coloringRules(readSettings(this.uri))); // compile errors are known now
      } else {
        void this.applyColoring(); // no colors yet, or the rules changed meanwhile
      }
      this.coloringStale = false;
    }
    return true;
  }

  private async openFile(client: BackendClient, settings: Settings): Promise<OpenResult> {
    return vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Window,
        title: `Indexing ${vscode.workspace.asRelativePath(this.uri)}`,
      },
      async (progress) => {
        const common = {
          lua: settings.luaScripts,
          decodeAs: settings.decodeAs,
          prefs: settings.prefs,
          names: settings.nameResolution,
          columns: settings.columns.map((c) => c.field),
          // Show the first rows while the rest is indexed.
          stream: true,
          // Colors come with the rows: the index pass evaluates the coloring rules.
          coloring: this.coloringRules(settings).length
            ? { rules: coloringPayload(this.coloringRules(settings)) }
            : undefined,
        };
        // A new capture's first load starts it; later loads (settings) open the file.
        const capture = this.document.captureRequest;
        const [method, params] = capture
          ? [
              "capture_start",
              {
                ...common,
                dest: this.uri.fsPath,
                interfaces: capture.interfaces,
                filter: capture.filter,
                limits: capture.limits,
                promiscuous: capture.promiscuous,
              },
            ]
          : [
              "open",
              {
                ...common,
                path: this.uri.fsPath,
                // Reuse saved indexes (not for unsaved captures: they are discarded).
                cache:
                  settings.indexCacheBytes > 0 && !this.document.temporary
                    ? { dir: indexCacheDir(this.context), maxBytes: settings.indexCacheBytes }
                    : undefined,
              },
            ];
        const pending = client.send<OpenResult>(method, params, {
          timeoutMs: 0,
          onProgress: (p) => {
            this.post({
              type: "progress",
              phase: p.phase,
              fraction: p.fraction,
              frames: p.frames,
            });
            if (typeof p.frames === "number") {
              progress.report({ message: `${p.frames.toLocaleString()} packets` });
            }
          },
        });
        this.loading = { id: pending.id, client };
        try {
          const info = await pending.promise;
          if (capture && this.document.captureRequest === capture) {
            this.document.captureRequest = undefined; // started (a failed start is retried by Reload)
          }
          return info;
        } finally {
          this.loading = undefined;
        }
      },
    );
  }

  /** tshark doesn't recognise the file (e.g. a text *.log opened with "Reopen Editor With…"). */
  /**
   * tshark reads files, and this capture is somewhere else (Live Share, an
   * archive or another virtual file system): offer to open a copy, which is
   * an unsaved capture (saving it asks where).
   */
  private notOnDisk(): void {
    const name = copyName(this.uri);
    const message =
      `${name} isn't a file on disk (${this.uri.scheme}:), and tshark can only read files.\n\n` +
      'Use "Open a Copy" to open a copy of it; saving the copy asks where to keep it.';
    this.log.warn(`${this.uri.toString()}: not a file on disk`);
    this.post({ type: "error", message, canReload: false });
    void vscode.window
      .showWarningMessage(`PCAP Lens: ${name} isn't a file on disk.`, "Open a Copy")
      .then(async (choice) => {
        if (!choice) {
          return;
        }
        try {
          await openCopy(this.context, this.uri);
        } catch (err) {
          void vscode.window.showErrorMessage(
            `PCAP Lens: could not copy ${name}: ${describeError(err)}`,
          );
        }
      });
  }

  private unsupportedFormat(err: RpcError): void {
    const name = path.basename(this.uri.fsPath);
    const data = err.data as { stderr?: string; berRecords?: number } | undefined;
    this.log.warn(`${this.uri.fsPath}: ${data?.stderr ?? err.message}`);
    const records = data?.berRecords;
    const reopen = "Reopen Editor With…";
    if (records) {
      // Several BER values back to back: tshark reads one per file, but they open as packets.
      const count = records.toLocaleString();
      this.post({
        type: "error",
        message:
          `${name} holds ${count} BER records one after another, and tshark reads a file of one BER value only.\n\n` +
          `Use "${OPEN_AS_PACKETS}" to open them as packets, one per record.`,
        canReload: true,
      });
    } else {
      this.post({
        type: "error",
        message:
          `${name} is not a capture file that tshark can read.\n\n` +
          "PCAP Lens opens pcap and pcapng (also gzip, zstd or lz4 compressed) and the other capture formats Wireshark supports, " +
          `such as snoop, ERF, btsnoop and PacketLogger. Use "${reopen}" to open this file with another editor.`,
        canReload: true,
      });
    }
    const buttons = records ? [OPEN_AS_PACKETS, reopen] : [reopen];
    void vscode.window
      .showWarningMessage(
        records
          ? `PCAP Lens: ${name} holds ${records.toLocaleString()} BER records one after another.`
          : `PCAP Lens: ${name} is not a capture file that tshark can read.`,
        ...buttons,
      )
      .then((choice) => {
        if (choice === OPEN_AS_PACKETS) {
          void vscode.commands.executeCommand("pcapViewer.openBerRecords", { uri: this.uri });
        } else if (choice) {
          // The command reopens the active editor: make it this one first.
          this.reveal();
          void vscode.commands.executeCommand("workbench.action.reopenWithEditor");
        }
      });
  }

  private fail(message: string, setting?: "tsharkPath" | "pythonPath"): void {
    this.log.error(`${this.uri.fsPath}: ${message}`);
    this.post({ type: "error", message, canReload: true });
    if (setting) {
      setEnvironmentContext(setting !== "pythonPath", false);
      void offerSetupHelp(this.context, message, setting);
      return;
    }
    void vscode.window.showErrorMessage(`PCAP Lens: ${message}`, "Show Log").then((choice) => {
      if (choice === "Show Log") {
        this.log.show();
      }
    });
  }

  private async onMessage(msg: WebviewToHost): Promise<void> {
    switch (msg.type) {
      case "ready":
        return;
      case "runCommand":
        await this.runMenuCommand(msg.id);
        return;
      case "rpc":
        return this.forwardRpc(msg.id, msg.method, msg.params);
      case "cancel": {
        const backendId = this.inflight.get(msg.id);
        if (backendId !== undefined) {
          this.client?.cancel(backendId);
        }
        return;
      }
      case "cancelLoad":
        if (this.loading) {
          this.loading.client.cancel(this.loading.id);
        }
        return;
      case "reload":
        return this.load("Reload");
      case "filterApplied":
        this.filter = msg.expr;
        this.filterEmitter.fire(msg.expr);
        if (msg.expr.trim()) {
          void vscode.commands.executeCommand("setContext", FILTER_APPLIED, true);
          const history = pushHistory(this.history(), msg.expr);
          await this.context.globalState.update(HISTORY_KEY, history);
          this.post({ type: "history", history });
        }
        return;
      case "saveFilter":
        await saveFilterInteractive(msg.expr, this);
        return;
      case "manageSavedFilters":
        await showSavedFilters(this);
        return;
      case "addFilterButton":
        await addFilterButtonInteractive(typeof msg.filter === "string" ? msg.filter : "", this);
        return;
      case "editFilterButton":
        if (Number.isInteger(msg.index)) {
          await editFilterButton(
            msg.index,
            typeof msg.filter === "string" ? msg.filter : undefined,
            this,
          );
        }
        return;
      case "selection":
        this.selectedFrame = typeof msg.frame === "number" ? msg.frame : null;
        this.selectedFrames = Array.isArray(msg.frames)
          ? msg.frames.filter((n) => Number.isInteger(n))
          : [];
        return;
      case "follow":
        if (Object.hasOwn(FOLLOW_LABELS, msg.proto)) {
          FollowPanel.show(this.context, this, msg.proto, msg.frame);
        }
        return;
      case "tcpGraph":
        await vscode.commands.executeCommand("pcapViewer.statistics.tcpStreamGraph", msg.frame);
        return;
      case "decodeAs":
        await vscode.commands.executeCommand("pcapViewer.decodeAs", msg.frame);
        return;
      case "compare":
        await vscode.commands.executeCommand("pcapViewer.comparePackets", {
          frames: Array.isArray(msg.frames) ? msg.frames.slice(0, 2) : [],
        });
        return;
      case "protocolPrefs":
        await vscode.commands.executeCommand("pcapViewer.protocolPreferences", {
          protocol: msg.protocol,
        });
        return;
      case "colorize":
        await vscode.commands.executeCommand("pcapViewer.colorizeWithFilter", msg.filter);
        return;
      case "colorizeConversation":
        if (typeof msg.filter === "string" && msg.filter.trim() && !msg.filter.includes("@")) {
          void this.colorizeConversation(msg.filter.trim());
        }
        return;
      case "aiSuggest":
        return this.aiSuggest(msg.id, msg.request);
      case "aiCancel":
        this.aiRequests.get(msg.id)?.cancel();
        return;
      case "exportBytes":
        await vscode.commands.executeCommand("pcapViewer.exportPacketBytes", msg.frame);
        return;
      case "applyColumn":
        await this.updateColumns((cols) => addColumn(cols, msg.field, msg.title));
        vscode.window.setStatusBarMessage(`Added column ${msg.title || msg.field}`, 3000);
        return;
      case "removeColumn":
        await this.updateColumns((cols) => cols.filter((c) => c.field !== msg.field));
        return;
      case "renameColumn": {
        const current = readSettings(this.uri).columns.find((c) => c.field === msg.field);
        const title = await vscode.window.showInputBox({
          title: `Rename column ${msg.field}`,
          value: current?.title ?? msg.field,
        });
        if (title !== undefined) {
          await this.updateColumns((cols) =>
            cols.map((c) => (c.field === msg.field ? { ...c, title: title.trim() || c.field } : c)),
          );
        }
        return;
      }
      case "columnLayout":
        await updateSetting("columnLayout", msg.layout, this.uri);
        return;
      case "pickTimeFormat":
        await vscode.commands.executeCommand("pcapViewer.timeFormat");
        return;
      case "pickNameResolution":
        await vscode.commands.executeCommand("pcapViewer.nameResolution");
        return;
      case "pickLuaDissectors":
        this.activate(); // (the command acts on the active capture)
        await vscode.commands.executeCommand("pcapViewer.chooseLuaDissectors");
        return;
      case "setComment":
        this.editComments(
          new Map([[msg.frame, msg.text]]),
          msg.text ? "Edit Packet Comment" : "Delete Packet Comment",
        );
        return;
      case "exportMarked":
        await vscode.commands.executeCommand("pcapViewer.exportMarked");
        return;
      case "exportSelected":
        await vscode.commands.executeCommand("pcapViewer.exportSelected");
        return;
      case "askAboutPackets":
        await vscode.commands.executeCommand(
          "pcapViewer.askAboutPackets",
          msg.frames.filter((n) => Number.isInteger(n)),
        );
        return;
      case "marks":
        this.markedCount = msg.count;
        return;
      case "copy":
        await vscode.env.clipboard.writeText(String(msg.text));
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
      case "stopCapture":
        await this.stopCapture();
        return;
      case "showLog":
        this.log.show();
        return;
    }
  }

  // ------------------------------------------------------------------ live capture

  /** The backend's "capture" notification: statistics go to the viewer; the end is reported. */
  private onCaptureEvent(client: BackendClient, p: CaptureEvent): void {
    if (this.client !== client || this.disposed) {
      return;
    }
    this.post({ type: "captureEvent", ...p });
    if (p.event !== "stopped") {
      return;
    }
    const name = path.basename(this.uri.fsPath);
    this.log.info(
      `${name}: capture stopped after ${p.packets} packets, ${p.bytes} bytes` +
        (p.dropped ? `, ${p.dropped} dropped` : ""),
    );
    if (p.error) {
      this.log.error(`${name}: ${p.error}`);
      void vscode.window
        .showErrorMessage(`PCAP Lens: the capture stopped: ${p.error}`, "Show Log")
        .then((choice) => choice && this.log.show());
    }
    this.capturing = false;
    this.captureEmitter.fire();
  }

  /** Stop the live capture; with `wait`, until its last packets are indexed. */
  async stopCapture(wait = false): Promise<void> {
    const client = this.client;
    if (!client?.running || !this.capturing) {
      return;
    }
    const indexed = this.whenIndexed();
    await client.request("capture_stop", {});
    if (wait) {
      await indexed;
    }
  }

  /** Resolves once the index pass is done (at once when it is). */
  whenIndexed(): Promise<void> {
    return this.indexing
      ? new Promise((resolve) => this.indexedWaiters.push(resolve))
      : Promise.resolve();
  }

  private async forwardRpc(
    id: number,
    method: string,
    params: Record<string, unknown>,
  ): Promise<void> {
    if (!WEBVIEW_RPC_METHODS.has(method)) {
      this.post({
        type: "rpcError",
        id,
        error: { code: ErrorCodes.MethodNotFound, message: `method not allowed: ${method}` },
      });
      return;
    }
    const client = this.client;
    if (!client?.running) {
      this.post({
        type: "rpcError",
        id,
        error: { code: ErrorCodes.BackendExited, message: "The PCAP backend is not running" },
      });
      return;
    }
    // Long-running methods are cancellable instead of timed out.
    const longRunning =
      method === "set_filter" || method === "list_packets" || method === "packet_detail";
    const pending = client.send(method, params ?? {}, {
      timeoutMs: longRunning ? 0 : undefined,
      onProgress: (p) =>
        this.post({
          type: "progress",
          id,
          phase: p.phase,
          fraction: p.fraction,
          frames: p.frames,
          matched: p.matched,
        }),
    });
    this.inflight.set(id, pending.id);
    try {
      const result = await pending.promise;
      this.post({ type: "rpcResult", id, result });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      if (!e.cancelled && e.code !== ErrorCodes.InvalidFilter) {
        this.log.warn(`${method} failed: ${e.message}`);
      }
      this.post({
        type: "rpcError",
        id,
        error: { code: e.code, message: e.message, data: e.data },
      });
    } finally {
      this.inflight.delete(id);
    }
  }

  // ------------------------------------------------------------------ coloring

  /** The rules to apply: colorized conversations (even with coloring off), then the configured ones. */
  private coloringRules(settings: Settings): ColoringRule[] {
    return [...this.temporaryRules, ...configuredRules(settings)].slice(0, MAX_COLORING_RULES);
  }

  /** Colorize Conversation: color the packets of `filter` in this editor until reset. */
  colorizeConversation(filter: string): Promise<void> {
    this.temporaryRules = colorizeConversation(this.temporaryRules, filter);
    return this.applyColoring();
  }

  /** Reset Colorization: drop the colorized conversations (false when there were none). */
  resetColorization(): boolean {
    if (!this.temporaryRules.length) {
      return false;
    }
    this.temporaryRules = [];
    void this.applyColoring();
    return true;
  }

  /**
   * Evaluate the coloring rules in the backend (one tshark pass, in the
   * background) and send the palette to the webview once rows carry colors.
   * A newer call cancels a running one.
   */
  async applyColoring(): Promise<void> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return;
    }
    if (this.indexing) {
      this.coloringStale = true; // a coloring pass needs every packet: when indexing is done
      return;
    }
    if (this.coloring?.client === client) {
      client.cancel(this.coloring.id);
    }
    const rules = this.coloringRules(readSettings(this.uri));
    if (rules.length) {
      this.post({ type: "coloringProgress", fraction: null });
    }
    const pending = client.send<ColoringResult>(
      "set_coloring",
      { rules: coloringPayload(rules) },
      {
        timeoutMs: 0,
        onProgress: (p) =>
          this.post({
            type: "coloringProgress",
            fraction: typeof p.fraction === "number" ? p.fraction : null,
          }),
      },
    );
    const coloring = { id: pending.id, client };
    this.coloring = coloring;
    let result: ColoringResult;
    try {
      result = await (rules.length
        ? vscode.window.withProgress(
            { location: vscode.ProgressLocation.Window, title: "Colorizing packets" },
            () => pending.promise,
          )
        : pending.promise);
    } catch (err) {
      if (!(err instanceof RpcError && err.cancelled) && this.client === client) {
        this.log.warn(`${this.uri.fsPath}: coloring failed: ${describeError(err)}`);
      }
      if (this.coloring === coloring) {
        this.post({ type: "coloringProgress", fraction: null, done: true });
      }
      return;
    } finally {
      if (this.coloring === coloring) {
        this.coloring = undefined;
      }
    }
    if (this.client !== client || this.disposed) {
      return;
    }
    this.showColoring(result, rules);
  }

  /** Report rules that were skipped, and give the viewer the palette of `result`'s colors. */
  private showColoring(result: ColoringResult, rules: ColoringRule[]): void {
    const problems = Object.entries(result.errors).map(
      ([i, message]) => `Coloring rule "${rules[Number(i)]?.name ?? i}" skipped: ${message}`,
    );
    for (const p of problems) {
      this.log.warn(p);
    }
    const fresh = problems.filter((p) => !reportedColoringErrors.has(p));
    if (fresh.length) {
      fresh.forEach((p) => reportedColoringErrors.add(p));
      void vscode.window
        .showWarningMessage(
          `PCAP Lens: ${fresh[0]}${fresh.length > 1 ? ` (+${fresh.length - 1} more)` : ""}`,
          "Edit Rules",
          "Show Log",
        )
        .then((choice) => {
          if (choice === "Edit Rules") {
            void vscode.commands.executeCommand("pcapViewer.manageColoringRules");
          } else if (choice === "Show Log") {
            this.log.show();
          }
        });
    }
    this.post({
      type: "coloring",
      coloringId: result.coloringId,
      temporary: rules.filter((r) => r.temporary).length,
      rules: rules.map((r) => ({
        name: r.name,
        foreground: r.foreground,
        background: r.background,
      })),
    });
  }

  // ------------------------------------------------------------------ AI filter help

  private async postAiAvailability(): Promise<void> {
    this.post({
      type: "aiAvailable",
      available: !!this.info && (await this.assistant.isAvailable()),
    });
  }

  /** Validated display filters for a natural-language request (see ai.ts; no packet data is sent). */
  async suggestFilters(request: string, token: vscode.CancellationToken): Promise<SuggestOutcome> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return { suggestions: [], rejected: [], message: "Wait for the capture to finish loading." };
    }
    const outcome = await this.assistant.suggest(client, request, this.filter, token);
    if (outcome.unavailable) {
      this.post({ type: "aiAvailable", available: false });
    }
    return outcome;
  }

  /**
   * Explain packets with the language model (ai.ts). Sends their rows and
   * dissection trees: callers must have the user's consent (commands/ai.ts).
   */
  async explainPackets(
    frames: number[],
    question: string,
    includeBytes: boolean,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return { frames: [], filters: [], message: "Wait for the capture to finish loading." };
    }
    const custom = readSettings(this.uri).columns;
    const titleOf: Record<string, string> = {};
    for (const c of this.info.columns) {
      titleOf[c.field] = c.title;
    }
    for (const c of custom) {
      titleOf[c.field] = c.title || c.field;
    }
    return this.assistant.explain(
      client,
      {
        frames,
        question,
        currentFilter: this.filter,
        titleOf,
        customFields: custom.map((c) => c.field),
        includeBytes,
        quickDetail: readQuickDetail(this.uri),
      },
      sink,
      token,
    );
  }

  /** Whether AI help can be used now (a language model is available and allowed). */
  async aiAvailable(): Promise<boolean> {
    return !!this.info && (await this.assistant.isAvailable());
  }

  /** Whether @pcap can answer with language model tools in this VS Code. */
  get toolsAvailable(): boolean {
    return this.assistant.toolsAvailable();
  }

  private notLoaded(): ExplainOutcome {
    return { frames: [], filters: [], message: "Wait for the capture to finish loading." };
  }

  /** Summarize the capture from its statistics (ai.ts; the caller has the statistics consent). */
  async summarize(
    question: string,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const client = this.client;
    if (!client?.running || !this.info || this.info.indexing || this.capturing) {
      return this.notLoaded();
    }
    return this.assistant.summarize(client, { question, currentFilter: this.filter }, sink, token);
  }

  /** Explain expert information or a TCP stream (ai.ts; the caller has the statistics consent). */
  async explainAnomaly(
    req: Omit<AnomalyRequest, "currentFilter">,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return this.notLoaded();
    }
    return this.assistant.explainAnomaly(
      client,
      { ...req, currentFilter: this.filter },
      sink,
      token,
    );
  }

  /** Answer a question with read-only language model tools (ai.ts, aiTools.ts). */
  async answerWithTools(
    question: string,
    consent: ToolConsent,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return this.notLoaded();
    }
    return this.assistant.answerWithTools(
      client,
      { question, currentFilter: this.filter, consent },
      sink,
      token,
    );
  }

  private async aiSuggest(id: number, request: string): Promise<void> {
    const cts = new vscode.CancellationTokenSource();
    this.aiRequests.set(id, cts);
    try {
      const outcome = await this.suggestFilters(request, cts.token);
      this.post({
        type: "aiSuggestions",
        id,
        suggestions: outcome.suggestions,
        message: outcome.message,
      });
    } finally {
      this.aiRequests.delete(id);
      cts.dispose();
    }
  }

  // ------------------------------------------------------------------ commands

  applyFilter(expr: string): void {
    this.post({ type: "applyFilter", expr });
  }

  /** Put a filter in the filter bar without applying it ("Prepare as Filter"). */
  prepareFilter(expr: string): void {
    this.post({ type: "prepareFilter", expr });
  }

  /** Called by this capture's panels when they gain focus. */
  activate(): void {
    this.activateEmitter.fire();
  }

  /** The ☰ menu's commands, as sent to this webview. */
  get menuCommands(): MenuCommand[] {
    return commandMenu(this.context);
  }

  /**
   * Run a ☰ menu entry on this capture: only a `pcapViewer.*` id from the list
   * this webview was sent (anything else is ignored), with this session made
   * the active one first, since commands act on `provider.activeSession`.
   * Returns whether it ran.
   */
  async runMenuCommand(id: unknown): Promise<boolean> {
    if (typeof id !== "string" || !this.menuCommands.some((c) => c.id === id)) {
      this.log.warn(`ignored a request to run ${JSON.stringify(id)} from the viewer`);
      return false;
    }
    this.activate();
    try {
      await vscode.commands.executeCommand(id);
    } catch (err) {
      this.log.error(`${id} failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    return true;
  }

  /** Bring the capture editor to the front (e.g. after a panel applied a filter). */
  reveal(): void {
    // In its own column: without one VS Code reveals it in the active group,
    // usually the panel's beside it, opening the capture there too and moving
    // the webview, which left the first tab empty.
    this.panel.reveal(this.panel.viewColumn, false);
  }

  focusFilter(): void {
    this.post({ type: "focusFilter" });
  }

  goTo(frame: number): void {
    this.post({ type: "goto", number: frame });
  }

  setColumns(columns: ColumnSetting[], layout: ColumnLayout): void {
    this.post({ type: "columns", columns, layout });
  }

  setTimeFormat(format: TimeFormat): void {
    this.post({ type: "timeFormat", format });
  }

  setQuickDetail(quickDetail: QuickDetail): void {
    this.post({ type: "quickDetail", quickDetail });
  }

  /** Run a viewer action (Find, marks, navigation…) from the command palette or a keybinding. */
  runCommand(command: ViewerCommand): void {
    this.post({ type: "command", command });
  }

  /** Change pcapViewer.columns for this capture's folder (raw entries are normalised first). */
  private async updateColumns(
    change: (columns: ColumnSetting[]) => ColumnSetting[],
  ): Promise<void> {
    const current = normalizeColumns(getSetting<unknown>("columns", [], this.uri));
    await updateSetting("columns", change(current), this.uri);
  }

  setSavedFilters(savedFilters: SavedFilter[]): void {
    this.post({ type: "savedFilters", savedFilters });
  }

  setColoringStyle(style: ColoringStyle): void {
    this.post({ type: "coloringStyle", style });
  }

  setFilterButtons(buttons: FilterButton[]): void {
    this.post({ type: "filterButtons", buttons });
  }

  async validateFilter(expr: string): Promise<string | undefined> {
    if (!this.client?.running) {
      return undefined;
    }
    try {
      const res = await this.client.request<{ valid: boolean; error?: string }>("validate_filter", {
        expr,
      });
      return res.valid ? undefined : res.error;
    } catch {
      return undefined;
    }
  }

  // ------------------------------------------------------------------ plumbing

  private history(): string[] {
    return this.context.globalState.get<string[]>(HISTORY_KEY, []);
  }

  /** An export of this capture: its progress in the viewer's progress bar (`done` hides it). */
  showExportProgress(fraction: number | null, done = false): void {
    this.post({ type: "exportProgress", fraction, done: done || undefined });
  }

  private post(msg: HostToWebview): void {
    if (!this.disposed) {
      void this.panel.webview.postMessage(msg);
    }
  }

  private async stopBackend(): Promise<void> {
    const client = this.client;
    this.client = undefined;
    this.info = undefined;
    this.coloring = undefined;
    this.inflight.clear();
    for (const cts of this.aiRequests.values()) {
      cts.cancel();
    }
    if (client) {
      await client.dispose();
    }
  }

  async dispose(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.loadSeq++;
    this.keyLogWatcher?.dispose();
    this.disposeEmitter.fire();
    this.disposeEmitter.dispose();
    this.activateEmitter.dispose();
    this.indexedWaiters.splice(0).forEach((resolve) => resolve());
    this.capturing = false;
    this.captureEmitter.fire();
    this.captureEmitter.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
    await this.stopBackend();
  }

  private renderHtml(root: vscode.Uri): string {
    const webview = this.panel.webview;
    const nonce = crypto.randomBytes(16).toString("base64");
    const template = fs.readFileSync(vscode.Uri.joinPath(root, "index.html").fsPath, "utf8");
    const values: Record<string, string> = {
      cspSource: webview.cspSource,
      nonce,
      baseUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "base.css")).toString(),
      stylesUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "styles.css")).toString(),
      codiconsUri: webview
        .asWebviewUri(vscode.Uri.joinPath(root, "codicons", "codicon.css"))
        .toString(),
      libUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "lib.js")).toString(),
      mainUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "main.js")).toString(),
    };
    return template.replace(/\{\{(\w+)\}\}/g, (_m, key: string) => values[key] ?? "");
  }
}

export function describeError(err: unknown): string {
  if (err instanceof RpcError) {
    const stderr = (err.data as { stderr?: string } | undefined)?.stderr;
    return stderr && !err.message.includes(stderr) ? `${err.message}\n${stderr}` : err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
