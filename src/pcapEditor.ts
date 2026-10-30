import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { discardTemporaryCapture, isTemporaryCapture } from "./tempCaptures";
import type { FilterAssistant } from "./ai";
import { exportFileName, parseCommentBackup } from "./settingsModel";
import { CaptureRequest, PcapDocument } from "./pcapDocument";
import { PcapEditorSession } from "./editorSession";

/**
 * Custom editor for capture files. Each editor panel owns one backend process
 * (the backend keeps per-view filter/sort state). Packet comments are the one
 * edit: VS Code tracks them (dirty state, undo/redo, save, hot-exit backups).
 */
export class PcapEditorProvider implements vscode.CustomEditorProvider<PcapDocument> {
  /** Default editor for unambiguous capture files (package.json customEditors). */
  static readonly viewType = "pcapViewer.editor";
  /** Same editor, only offered in "Reopen Editor With…" for generic extensions (*.log, *.1…). */
  static readonly optionalViewType = "pcapViewer.editorOptional";

  private readonly sessions = new Set<PcapEditorSession>();
  private active?: PcapEditorSession;
  private readonly changeEmitter = new vscode.EventEmitter<
    | vscode.CustomDocumentEditEvent<PcapDocument>
    | vscode.CustomDocumentContentChangeEvent<PcapDocument>
  >();
  readonly onDidChangeCustomDocument = this.changeEmitter.event;
  /** Captures to start, by the URI of the (empty) file their editor opens. */
  private readonly pendingCaptures = new Map<string, CaptureRequest>();

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly log: vscode.LogOutputChannel,
    private readonly assistant: FilterAssistant,
  ) {}

  static register(
    context: vscode.ExtensionContext,
    log: vscode.LogOutputChannel,
    assistant: FilterAssistant,
  ): PcapEditorProvider {
    const provider = new PcapEditorProvider(context, log, assistant);
    const options = {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: true,
    };
    context.subscriptions.push(
      vscode.window.registerCustomEditorProvider(PcapEditorProvider.viewType, provider, options),
      vscode.window.registerCustomEditorProvider(
        PcapEditorProvider.optionalViewType,
        provider,
        options,
      ),
    );
    return provider;
  }

  async openCustomDocument(
    uri: vscode.Uri,
    openContext: vscode.CustomDocumentOpenContext,
  ): Promise<PcapDocument> {
    let restored: Map<number, string> | undefined;
    if (openContext.backupId) {
      try {
        const raw = await vscode.workspace.fs.readFile(vscode.Uri.parse(openContext.backupId));
        restored = parseCommentBackup(new TextDecoder().decode(raw));
      } catch (err) {
        this.log.warn(`could not restore unsaved packet comments: ${String(err)}`);
      }
    }
    const key = uri.toString();
    const capture = this.pendingCaptures.get(key);
    this.pendingCaptures.delete(key);
    const temporary = isTemporaryCapture(this.context, uri);
    return new PcapDocument(uri, restored, {
      temporary,
      capture,
      onDispose: temporary ? () => discardTemporaryCapture(this.context, uri.fsPath) : undefined,
    });
  }

  /** The next editor opened on `uri` starts this live capture into it. */
  queueCapture(uri: vscode.Uri, request: CaptureRequest): void {
    this.pendingCaptures.set(uri.toString(), request);
  }

  resolveCustomEditor(document: PcapDocument, panel: vscode.WebviewPanel): void {
    const session = new PcapEditorSession(
      this.context,
      document,
      panel,
      this.log,
      this.assistant,
      (changes, label) => this.editComments(document, changes, label),
    );
    this.sessions.add(session);
    this.setActive(session);
    panel.onDidChangeViewState(() => {
      if (panel.active) {
        this.setActive(session);
      }
    });
    // Focusing one of this capture's statistics/follow panels makes it the
    // target of capture commands too (not whichever editor was focused last).
    session.onDidActivate(() => this.setActive(session));
    session.onDidChangeCapture(() => this.updateContext());
    panel.onDidDispose(() => {
      this.sessions.delete(session);
      if (this.active === session) {
        this.setActive(undefined);
      }
      void session.dispose();
    });
    if (document.temporary && !document.markedUnsaved) {
      this.markUnsaved(document);
    }
  }

  private setActive(session: PcapEditorSession | undefined): void {
    this.active = session;
    this.updateContext();
  }

  /** `pcapViewer.capturing`: the active capture is live (Stop Capture in the editor
   * title); `pcapViewer.following`: its file is followed (Stop Following). */
  private updateContext(): void {
    const following = !!this.active?.following;
    void vscode.commands.executeCommand(
      "setContext",
      "pcapViewer.capturing",
      !!this.active?.capturing && !following,
    );
    void vscode.commands.executeCommand("setContext", "pcapViewer.following", following);
  }

  /** An unsaved capture: VS Code shows it dirty, so saving and closing ask what to do with it. */
  private markUnsaved(document: PcapDocument): void {
    document.markedUnsaved = true;
    this.changeEmitter.fire({ document });
  }

  get activeSession(): PcapEditorSession | undefined {
    return this.active;
  }

  /** Change comments (frame → text, "" deletes) as one undoable edit. */
  editComments(document: PcapDocument, changes: Map<number, string>, label: string): void {
    const before = new Map([...changes.keys()].map((n) => [n, document.editOf(n)]));
    const after = new Map<number, string | undefined>(changes);
    document.apply(after);
    this.changeEmitter.fire({
      document,
      label,
      undo: () => document.apply(before),
      redo: () => document.apply(after),
    });
  }

  async saveCustomDocument(
    document: PcapDocument,
    cancellation: vscode.CancellationToken,
  ): Promise<void> {
    if (document.temporary) {
      await this.saveTemporary(document, cancellation);
      return;
    }
    await this.saveComments(document, undefined, cancellation);
  }

  async saveCustomDocumentAs(
    document: PcapDocument,
    destination: vscode.Uri,
    cancellation: vscode.CancellationToken,
  ): Promise<void> {
    if (document.temporary) {
      await this.stopCaptureToSave(document);
    }
    await this.saveComments(document, destination, cancellation);
  }

  async revertCustomDocument(document: PcapDocument): Promise<void> {
    // (An unsaved capture then counts as discarded: closing it no longer asks.)
    document.clear(false);
  }

  /**
   * Save an unsaved capture: ask where (Save As), write it there with its
   * comment edits, open it, and close this one (which discards the temporary file).
   */
  private async saveTemporary(
    document: PcapDocument,
    cancellation: vscode.CancellationToken,
  ): Promise<void> {
    await this.stopCaptureToSave(document);
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();
    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(path.join(folder, path.basename(document.uri.fsPath))),
      filters: { "pcapng capture": ["pcapng"] },
      title: "Save Capture",
    });
    if (!target) {
      throw new vscode.CancellationError();
    }
    await this.saveComments(document, target, cancellation);
    await vscode.commands.executeCommand("vscode.openWith", target, PcapEditorProvider.viewType);
    setTimeout(() => void closeEditorsOf(document.uri), 0); // (once this save is done)
  }

  /** A capture still running is stopped (after asking) before it is saved. */
  private async stopCaptureToSave(document: PcapDocument): Promise<void> {
    const session = [...this.sessions].find((s) => s.document === document && s.capturing);
    if (!session) {
      return;
    }
    const choice = await vscode.window.showWarningMessage(
      "The capture is still running. Stop it and save the packets captured so far?",
      { modal: true },
      "Stop and Save",
    );
    if (!choice) {
      throw new vscode.CancellationError();
    }
    await session.stopCapture(true);
  }

  async backupCustomDocument(
    document: PcapDocument,
    context: vscode.CustomDocumentBackupContext,
  ): Promise<vscode.CustomDocumentBackup> {
    const data = new TextEncoder().encode(JSON.stringify(document.editsParam()));
    await vscode.workspace.fs.writeFile(context.destination, data);
    return {
      id: context.destination.toString(),
      delete: () => void vscode.workspace.fs.delete(context.destination).then(undefined, () => {}),
    };
  }

  /**
   * Write the comment edits with editcap: into the capture itself (plain
   * pcapng only; other formats can't hold comments, so they get a new
   * .pcapng, which then opens) or to `destination` (Save As).
   */
  private async saveComments(
    document: PcapDocument,
    destination: vscode.Uri | undefined,
    cancellation: vscode.CancellationToken,
  ): Promise<void> {
    const session = [...this.sessions].find((s) => s.document === document && s.backend?.running);
    const client = session?.backend;
    if (!session || !client) {
      throw new Error("The capture is not loaded (the PCAP backend is not running).");
    }
    const edits = document.editsParam();
    const inPlace = !destination || destination.fsPath === document.uri.fsPath;
    const request = (params: Record<string, unknown>) =>
      vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: "Saving packet comments" },
        () =>
          client.request<{ path: string; comments: number }>(
            "save_comments",
            { edits, ...params },
            { timeoutMs: 0, cancellation },
          ),
      );
    if (inPlace && session.openInfo?.comments?.inPlace) {
      document.savedAt = Date.now();
      try {
        await request({ inPlace: true });
      } finally {
        document.savedAt = Date.now();
      }
      document.clear(true);
      return;
    }
    let target = destination;
    if (inPlace) {
      const choice = await vscode.window.showWarningMessage(
        "Packet comments can only be saved in pcapng files. Save them in a new .pcapng file?",
        { modal: true },
        "Save As…",
      );
      target =
        choice &&
        (await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(exportFileName(document.uri.fsPath, "comments", "pcapng")),
          filters: { "pcapng capture": ["pcapng"] },
          title: "Save Packet Comments",
        }));
      if (!target) {
        throw new vscode.CancellationError();
      }
    }
    const saved = target!;
    await request({ dest: saved.fsPath });
    if (inPlace) {
      // The comments now live in the new file: open it; this capture is unchanged.
      document.clear(false);
      await vscode.commands.executeCommand("vscode.openWith", saved, PcapEditorProvider.viewType);
    }
  }

  get allSessions(): readonly PcapEditorSession[] {
    return [...this.sessions];
  }

  async disposeAll(): Promise<void> {
    await Promise.all([...this.sessions].map((s) => s.dispose()));
    this.sessions.clear();
  }
}

/**
 * Close the editor tabs showing `uri` once VS Code counts them saved (after an
 * unsaved capture was saved elsewhere; a dirty tab would ask again).
 */
async function closeEditorsOf(uri: vscode.Uri, attempts = 25): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    const tabs = vscode.window.tabGroups.all
      .flatMap((g) => g.tabs)
      .filter(
        (t) =>
          t.input instanceof vscode.TabInputCustom && t.input.uri.toString() === uri.toString(),
      );
    if (!tabs.length) {
      return;
    }
    if (tabs.every((t) => !t.isDirty)) {
      await vscode.window.tabGroups.close(tabs);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

// Moved out of this file; re-exported so importers keep using "./pcapEditor".
export { CaptureRequest, PcapDocument } from "./pcapDocument";
export {
  OPEN_AS_PACKETS,
  PcapEditorSession,
  describeError,
  dissectionOptions,
  indexCacheDir,
} from "./editorSession";
