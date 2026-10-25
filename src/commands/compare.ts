import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { BackendClient, findPython } from "../backendClient";
import { readSettings } from "../config";
import {
  PcapEditorProvider,
  PcapEditorSession,
  dissectionOptions,
  indexCacheDir,
} from "../pcapEditor";
import { pickFile } from "./openFile";

/**
 * The other capture of a comparison (`@pcap /compare`, _PCAP: Compare
 * Captures with AI…_): picking it, finding it from a chat argument, and its
 * profile (`capture_profile`), from its own editor when one has it loaded,
 * else from a short-lived backend that opens it with its settings (and the
 * saved indexes, so a second comparison is quick).
 */

export type Role = "before" | "after";

export interface OtherCapture {
  uri: vscode.Uri;
  /** Its role: the baseline ("before") or the later capture ("after"). */
  is: Role;
}

/** Pick the capture to compare the open one with, and which of the two is the baseline. */
export async function pickOtherCapture(
  session: PcapEditorSession,
): Promise<OtherCapture | undefined> {
  const name = path.basename(session.uri.fsPath);
  const uri = await pickFile(`Compare ${name} with…`);
  if (!uri) {
    return undefined;
  }
  if (uri.fsPath === session.uri.fsPath) {
    void vscode.window.showInformationMessage("Pick another capture to compare with.");
    return undefined;
  }
  const other = path.basename(uri.fsPath);
  const role = await vscode.window.showQuickPick(
    [
      {
        label: `${other} is the baseline`,
        description: `${name} is the later capture`,
        is: "before" as Role,
      },
      {
        label: `${name} is the baseline`,
        description: `${other} is the later capture`,
        is: "after" as Role,
      },
    ],
    { title: "Which capture is the baseline (before)?" },
  );
  return role ? { uri, is: role.is } : undefined;
}

/**
 * A capture named in chat: absolute, else relative to the open capture's
 * folder or a workspace folder. Undefined when there's no such file.
 */
export function resolveCapturePath(
  text: string,
  session: PcapEditorSession,
): vscode.Uri | undefined {
  const candidates = path.isAbsolute(text)
    ? [text]
    : [
        path.join(path.dirname(session.uri.fsPath), text),
        ...(vscode.workspace.workspaceFolders ?? [])
          .filter((f) => f.uri.scheme === "file")
          .map((f) => path.join(f.uri.fsPath, text)),
      ];
  const found = candidates.find((c) => fs.existsSync(c) && fs.statSync(c).isFile());
  return found ? vscode.Uri.file(found) : undefined;
}

/** The other capture's profile: from its editor when loaded, else a short-lived backend. */
export async function captureProfile(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  uri: vscode.Uri,
  token: vscode.CancellationToken,
): Promise<unknown> {
  for (const s of provider.allSessions) {
    if (s.uri.fsPath === uri.fsPath) {
      const profile = await s.profile(token);
      if (profile) {
        return profile;
      }
    }
  }
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
  const cancellation = token;
  try {
    client.start();
    await client.request(
      "initialize",
      { tsharkPath: settings.tsharkPath || undefined },
      { timeoutMs: 120_000, cancellation },
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
      { timeoutMs: 0, cancellation },
    );
    return await client.request("capture_profile", {}, { timeoutMs: 0, cancellation });
  } finally {
    await client.dispose();
  }
}
