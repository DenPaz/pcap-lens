/**
 * The capture a language model tool reads when its `capture` argument names
 * one (a file the user attached with `#file:`/`@file:` or named in chat):
 * finding the file (aiCapturePath.ts), checking the tools may read it (open
 * in the viewer, in Recent Captures, or in a workspace folder), and a backend
 * for it: its viewer's when open, else one of `ToolCaptures`' own, opened as
 * the viewer would (the capture's folder's settings, the saved indexes) and
 * kept for the next calls (a few at a time, closed after a while unused).
 */
import { createHash } from "node:crypto";
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
 * capture's folder (`near`'s first) and the workspace folders, then by file
 * name among the open and recent captures and (one match only) the workspace.
 */
export async function resolveToolCapture(
  text: string,
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  /** A capture whose folder a relative path is tried in first (the one a comparison starts from). */
  near?: vscode.Uri,
): Promise<vscode.Uri | string> {
  const { folders, open, recent } = readablePlaces(provider, context);
  const active = provider.activeSession;
  const dirs = [
    ...[near, active?.uri]
      .filter((u): u is vscode.Uri => u?.scheme === "file")
      .map((u) => path.dirname(u.fsPath)),
    ...folders,
  ];
  // (a path names one file: the first folder it is in wins, in the order above)
  let found = captureCandidates(text, dirs).filter(isFile).slice(0, 1);
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

/** The workspace folders, open captures and recent captures: the places tools may read from. */
function readablePlaces(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
): { folders: string[]; open: string[]; recent: string[] } {
  return {
    folders: (vscode.workspace.workspaceFolders ?? [])
      .filter((f) => f.uri.scheme === "file")
      .map((f) => f.uri.fsPath),
    open: provider.allSessions.filter((s) => s.uri.scheme === "file").map((s) => s.uri.fsPath),
    recent: parseRecent(context.globalState.get(RECENT_KEY)).map((e) => e.path),
  };
}

/** Whether the tools may read `uri` (see `resolveToolCapture`). */
export function toolsCanRead(
  uri: vscode.Uri,
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
): boolean {
  return uri.scheme === "file" && toolsMayRead(uri.fsPath, readablePlaces(provider, context));
}

/**
 * How a chat request names `uri` for the tools' `capture` argument: its path
 * in the workspace, else its file name (found among the open and recent
 * captures), so no home folder goes to the model.
 */
export function captureLabel(uri: vscode.Uri): string {
  const rel = vscode.workspace.asRelativePath(uri, false);
  return rel && rel !== uri.fsPath && !path.isAbsolute(rel) ? rel : path.basename(uri.fsPath);
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
  /** The file's size and modification time and the settings it was opened with: a change means opening it again. */
  stamp: string;
  /** Tool calls using it now: it is closed only when none is. */
  users: number;
  /** Replaced (the file or its settings changed) or evicted: closed when its last user is done. */
  retired?: boolean;
  timer?: ReturnType<typeof setTimeout>;
}

/**
 * What an open depends on: the file (size, modification time) and the
 * settings the viewer would open it with (dissection options and Lua scripts'
 * modification times; hashed, since the options hold decryption keys).
 */
function stampOf(uri: vscode.Uri): string {
  const st = fs.statSync(uri.fsPath);
  const settings = readSettings(uri);
  // (an edited Lua script changes dissection too)
  const scripts = settings.luaScripts.map((p) => {
    try {
      return fs.statSync(p).mtimeMs;
    } catch {
      return null;
    }
  });
  const options = JSON.stringify([dissectionOptions(settings), scripts]);
  return `${st.size}:${st.mtimeMs}:${createHash("sha256").update(options).digest("hex")}`;
}

/**
 * The tools' own backends for captures not open in the viewer: at most
 * `max` kept, the least recently used idle one closed first, each closed
 * after `idleMs` unused, all closed with the extension. A backend a tool call
 * is using is never closed under it: `acquire` gives a `release` the call
 * runs when done.
 */
export class ToolCaptures implements vscode.Disposable {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly log: vscode.LogOutputChannel,
    private readonly max = 2,
    private readonly idleMs = 5 * 60_000,
  ) {}

  /** A backend with `uri` opened (reused while the file and its settings are unchanged), held until `release`. */
  async acquire(uri: vscode.Uri): Promise<{ client: BackendClient; release: () => void }> {
    const key = uri.fsPath;
    const stamp = stampOf(uri);
    let entry = this.entries.get(key);
    if (entry && entry.stamp !== stamp) {
      this.close(key);
      entry = undefined;
    }
    if (!entry) {
      this.log.info(`AI tools: opening ${key} in a backend of their own`);
      const client = openCaptureBackend(this.context, this.log, uri);
      entry = { client, stamp, users: 0 };
      this.entries.set(key, entry);
      client.catch(() => {
        if (this.entries.get(key)?.client === client) {
          this.entries.delete(key);
        }
      });
    } else {
      // (most recently used last)
      this.entries.delete(key);
      this.entries.set(key, entry);
    }
    const held = entry;
    held.users++;
    clearTimeout(held.timer);
    this.trim();
    let released = false;
    const release = (): void => {
      if (released) {
        return;
      }
      released = true;
      held.users--;
      if (held.users > 0) {
        return;
      }
      if (held.retired) {
        this.dispose1(held);
        return;
      }
      held.timer = setTimeout(() => this.close(key, held), this.idleMs);
      this.trim();
    };
    let client: BackendClient;
    try {
      client = await held.client;
    } catch (err) {
      release();
      throw err;
    }
    if (!client.running) {
      release();
      this.close(key, held);
      return this.acquire(uri);
    }
    return { client, release };
  }

  /** Close the least recently used idle backends past `max` (busy ones wait for their release). */
  private trim(): void {
    for (const [key, entry] of this.entries) {
      if (this.entries.size <= this.max) {
        return;
      }
      if (entry.users === 0) {
        this.close(key, entry);
      }
    }
  }

  /** Forget `key`'s backend (`only` that entry, if given): closed now, or by its last user. */
  private close(key: string, only?: Entry): void {
    const entry = this.entries.get(key);
    if (!entry || (only && entry !== only)) {
      return;
    }
    this.entries.delete(key);
    clearTimeout(entry.timer);
    entry.retired = true;
    if (entry.users === 0) {
      this.dispose1(entry);
    }
  }

  private dispose1(entry: Entry): void {
    clearTimeout(entry.timer);
    void entry.client.then(
      (c) => c.dispose(),
      () => undefined,
    );
  }

  dispose(): void {
    for (const entry of this.entries.values()) {
      this.dispose1(entry);
    }
    this.entries.clear();
  }
}
