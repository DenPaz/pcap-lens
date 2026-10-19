/**
 * The Recent Captures view (PCAP Lens in the activity bar): the captures
 * opened lately with their packet counts, sizes and when, a click to open one
 * again, and, while it is empty, buttons to open a file, the sample capture
 * or start a capture (`viewsWelcome`).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import type { OpenResult } from "../messages";
import {
  forgetCapture,
  parseRecent,
  recentDescription,
  recentTooltip,
  rememberCapture,
  type RecentCapture,
} from "../recentCaptures";
import { revealFile } from "./reveal";

const STATE_KEY = "pcapViewer.recentCaptures";
export const RECENT_VIEW = "pcapViewer.recentCaptures";

class RecentItem extends vscode.TreeItem {
  constructor(
    readonly entry: RecentCapture,
    missing: boolean,
  ) {
    super(path.basename(entry.path), vscode.TreeItemCollapsibleState.None);
    const uri = vscode.Uri.file(entry.path);
    const now = Date.now();
    this.resourceUri = uri;
    this.description = missing ? "file not found" : recentDescription(entry, now);
    this.tooltip = recentTooltip(entry, now).join("\n");
    this.contextValue = missing ? "recentCaptureMissing" : "recentCapture";
    if (missing) {
      this.iconPath = new vscode.ThemeIcon("warning");
    } else {
      this.iconPath = new vscode.ThemeIcon("file-binary");
      // An explicit editor id opens any file name (see Open File in PCAP Lens).
      this.command = {
        command: "vscode.openWith",
        title: "Open",
        arguments: [uri, "pcapViewer.editor"],
      };
    }
  }
}

export class RecentCapturesProvider implements vscode.TreeDataProvider<RecentItem> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;

  constructor(private readonly memento: vscode.Memento) {}

  list(): RecentCapture[] {
    return parseRecent(this.memento.get(STATE_KEY));
  }

  async remember(uri: vscode.Uri, info: OpenResult): Promise<void> {
    const entry: RecentCapture = {
      path: uri.fsPath,
      frames: info.frames,
      size: info.size,
      startTime: info.startTime,
      endTime: info.endTime,
      fileType: info.fileType,
      linkType: info.linkType,
      openedAt: Date.now(),
    };
    await this.save(rememberCapture(this.list(), entry));
  }

  async forget(file: string): Promise<void> {
    await this.save(forgetCapture(this.list(), file));
  }

  async clear(): Promise<void> {
    await this.save([]);
  }

  private async save(list: RecentCapture[]): Promise<void> {
    await this.memento.update(STATE_KEY, list);
    this.changed.fire();
  }

  getTreeItem(item: RecentItem): vscode.TreeItem {
    return item;
  }

  async getChildren(item?: RecentItem): Promise<RecentItem[]> {
    if (item) {
      return [];
    }
    const list = this.list();
    const exists = await Promise.all(
      list.map((e) =>
        fs.promises.stat(e.path).then(
          (s) => s.isFile(),
          () => false,
        ),
      ),
    );
    return list.map((e, i) => new RecentItem(e, !exists[i]));
  }

  refresh(): void {
    this.changed.fire();
  }
}

let provider: RecentCapturesProvider | undefined;

/**
 * Remember a capture that was opened (or finished indexing: final counts).
 * Unsaved captures and files not on disk are left out by the caller.
 */
export function rememberRecentCapture(uri: vscode.Uri, info: OpenResult): void {
  void provider?.remember(uri, info);
}

export function registerRecentCaptures(context: vscode.ExtensionContext): RecentCapturesProvider {
  const p = new RecentCapturesProvider(context.globalState);
  provider = p;
  const view = vscode.window.createTreeView(RECENT_VIEW, { treeDataProvider: p });
  // The ages ("5 min ago") go stale; refresh whenever the view is shown again.
  context.subscriptions.push(
    view,
    view.onDidChangeVisibility((e) => {
      if (e.visible) {
        p.refresh();
      }
    }),
    vscode.commands.registerCommand("pcapViewer.showRecentCaptures", () =>
      vscode.commands.executeCommand(`${RECENT_VIEW}.focus`),
    ),
    vscode.commands.registerCommand("pcapViewer.recentCaptures.clear", () => p.clear()),
    vscode.commands.registerCommand("pcapViewer.recentCaptures.refresh", () => p.refresh()),
    vscode.commands.registerCommand("pcapViewer.recentCaptures.remove", (item?: RecentItem) =>
      item ? p.forget(item.entry.path) : undefined,
    ),
    vscode.commands.registerCommand("pcapViewer.recentCaptures.reveal", (item?: RecentItem) =>
      item ? revealFile(item.entry.path) : undefined,
    ),
    vscode.commands.registerCommand("pcapViewer.recentCaptures.copyPath", (item?: RecentItem) =>
      item ? vscode.env.clipboard.writeText(item.entry.path) : undefined,
    ),
  );
  return p;
}
