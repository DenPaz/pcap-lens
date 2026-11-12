/**
 * The capture a language model tool reads when its `capture` argument names
 * one (a file the user attached with `#file:`/`@file:` or named in chat):
 * finding the file (aiCapturePath.ts), checking the tools may read it (open
 * in the viewer, in Recent Captures, or in a workspace folder), and a backend
 * for it: its viewer's when open, else one of `ToolCaptures`' own, opened as
 * the viewer would (the capture's folder's settings, the saved indexes) and
 * kept for the next calls (a few at a time, closed after a while unused).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { byFileName, captureCandidates, toolsMayRead } from "../aiCapturePath";
import { BackendClient, findPython } from "../backendClient";
import { readSettings } from "../config";
import {
  PcapEditorProvider,
  PcapEditorSession,
  dissectionOptions,
  indexCacheDir,
} from "../pcapEditor";
import { parseRecent } from "../recentCaptures";

/** Recent Captures' globalState key (commands/recent.ts). */
const RECENT_KEY = "pcapViewer.recentCaptures";

const isFile = (p: string): boolean => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};

/**
 * The capture file `text` names, or why there is none it may read. Tried in
 * turn: the path itself (absolute or a `file:` URI), relative to the active
 * capture's folder and the workspace folders, then by file name among the
 * open and recent captures and (one match only) the workspace.
 */
export async function resolveToolCapture(
  text: string,
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
): Promise<vscode.Uri | string> {
  const folders = (vscode.workspace.workspaceFolders ?? [])
    .filter((f) => f.uri.scheme === "file")
    .map((f) => f.uri.fsPath);
  const open = provider.allSessions.filter((s) => s.uri.scheme === "file").map((s) => s.uri.fsPath);
  const recent = parseRecent(context.globalState.get(RECENT_KEY)).map((e) => e.path);
  const active = provider.activeSession;
  const dirs = [
    ...(active?.uri.scheme === "file" ? [path.dirname(active.uri.fsPath)] : []),
    ...folders,
  ];
  let found = captureCandidates(text, dirs).filter(isFile);
  if (!found.length) {
    found = byFileName(text, [...open, ...recent]).filter(isFile);
  }
  const name = path.basename(text.trim());
  if (!found.length && /^[\w .()+-]+$/.test(name)) {
    const matches = await vscode.workspace.findFiles(`**/${name}`, undefined, 5);
    found = matches.filter((u) => u.scheme === "file").map((u) => u.fsPath);
  }
  if (!found.length) {
    return `No capture file ${text}: give its path (absolute, or relative to a workspace folder).`;
  }
  if (found.length > 1) {
    return `Several captures are named ${name}; give the path of one: ${found.slice(0, 5).join(", ")}.`;
  }
  const file = found[0];
  if (!toolsMayRead(file, { open, recent, folders })) {
    return `PCAP Lens's tools read captures in the workspace folders, open in the viewer or in Recent Captures; ${file} is none of those. Open it in PCAP Lens first.`;
  }
  return vscode.Uri.file(file);
}

/** The loaded viewer of `uri`, if one is open (and done loading enough to answer). */
export function viewerOf(
  provider: PcapEditorProvider,
  uri: vscode.Uri,
): PcapEditorSession | undefined {
  return provider.allSessions.find(
    (s) => s.uri.fsPath === uri.fsPath && !!s.openInfo && !!s.backend?.running,
  );
}

/**
 * A backend of its own with `uri` opened, as the viewer would open it (the
 * capture's folder's settings, the saved indexes, which make a second open
 * instant). The caller disposes it.
 */
export async function openCaptureBackend(
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  uri: vscode.Uri,
  token?: vscode.CancellationToken,
): Promise<BackendClient> {
  const settings = readSettings(uri);
  const py = findPython(settings.pythonPath || undefined);
  if ("error" in py) {
    throw new Error(py.error);
  }
  const client = new BackendClient({
    python: py.python,
    backendDir: vscode.Uri.joinPath(context.extensionUri, "backend").fsPath,
    logger: { info: (m) => log.info(m), warn: (m) => log.warn(m), error: (m) => log.error(m) },
  });
  try {
    client.start();
    await client.request(
      "initialize",
      { tsharkPath: settings.tsharkPath || undefined },
      { timeoutMs: 120_000, cancellation: token },
    );
    await client.request(
      "open",
      {
        ...dissectionOptions(settings),
        path: uri.fsPath,
        cache:
          settings.indexCacheBytes > 0
            ? { dir: indexCacheDir(context), maxBytes: settings.indexCacheBytes }
            : undefined,
      },
      { timeoutMs: 0, cancellation: token },
    );
    return client;
  } catch (err) {
    await client.dispose();
    throw err;
  }
}

interface Entry {
  client: Promise<BackendClient>;
  /** The file's size and modification time when opened: a change means opening it again. */
  stamp: string;
  timer?: ReturnType<typeof setTimeout>;
}

/**
 * The tools' own backends for captures not open in the viewer: at most
 * `max`, the least recently used closed first, each closed after `idleMs`
 * unused, all closed with the extension.
 */
export class ToolCaptures implements vscode.Disposable {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly log: vscode.LogOutputChannel,
    private readonly max = 2,
    private readonly idleMs = 5 * 60_000,
  ) {}

  /** A backend with `uri` opened (reused while the file is unchanged). */
  async backend(uri: vscode.Uri): Promise<BackendClient> {
    const key = uri.fsPath;
    const st = fs.statSync(key);
    const stamp = `${st.size}:${st.mtimeMs}`;
    let entry = this.entries.get(key);
    if (entry && entry.stamp !== stamp) {
      this.close(key);
      entry = undefined;
    }
    if (!entry) {
      this.log.info(`AI tools: opening ${key} in a backend of their own`);
      const client = openCaptureBackend(this.context, this.log, uri);
      entry = { client, stamp };
      this.entries.set(key, entry);
      client.catch(() => {
        if (this.entries.get(key)?.client === client) {
          this.entries.delete(key);
        }
      });
      for (const old of [...this.entries.keys()].slice(
        0,
        Math.max(0, this.entries.size - this.max),
      )) {
        this.close(old);
      }
    } else {
      // (most recently used last)
      this.entries.delete(key);
      this.entries.set(key, entry);
    }
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => this.close(key), this.idleMs);
    const client = await entry.client;
    if (!client.running) {
      this.close(key);
      return this.backend(uri);
    }
    return client;
  }

  private close(key: string): void {
    const entry = this.entries.get(key);
    if (!entry) {
      return;
    }
    this.entries.delete(key);
    clearTimeout(entry.timer);
    void entry.client.then(
      (c) => c.dispose(),
      () => undefined,
    );
  }

  dispose(): void {
    for (const key of [...this.entries.keys()]) {
      this.close(key);
    }
  }
}
