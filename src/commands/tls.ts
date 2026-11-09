import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import type { PcapEditorProvider } from "../pcapEditor";
import { looksLikeKeyLog } from "../settingsModel";

async function readStart(file: string, bytes = 64 * 1024): Promise<string> {
  const fh = await fs.open(file, "r");
  try {
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await fh.read(buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } finally {
    await fh.close();
  }
}

/**
 * "PCAP: Set TLS Key Log File…": pick an SSLKEYLOGFILE key log for the active
 * capture's folder (pcapViewer.tlsKeyLogFile), or stop using the current one.
 * The setting change reloads the captures it applies to (see extension.ts).
 */
export async function setTlsKeyLogFile(
  provider: PcapEditorProvider,
  args?: unknown,
): Promise<void> {
  const scope = provider.activeSession?.uri;
  const current = readSettings(scope).tlsKeyLogFile;
  // {file} or {clear: true} skip the questions; a file that isn't a key log is refused.
  const given = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
  if (given.clear === true) {
    await updateSetting("tlsKeyLogFile", "", scope);
    return;
  }
  const givenFile = typeof given.file === "string" && given.file ? given.file : undefined;
  if (current && !givenFile) {
    const pick = await vscode.window.showQuickPick(
      [
        { label: "$(file) Choose a Different Key Log File…", id: "choose" },
        { label: "$(close) Stop Using the Key Log File", description: current, id: "clear" },
      ],
      { title: "TLS Key Log File", placeHolder: `TLS is decrypted with ${path.basename(current)}` },
    );
    if (!pick) {
      return;
    }
    if (pick.id === "clear") {
      await updateSetting("tlsKeyLogFile", "", scope);
      return;
    }
  }
  const start = current ? path.dirname(current) : scope ? path.dirname(scope.fsPath) : undefined;
  // A given path is stored as given (a Uri's fsPath would lower-case a
  // Windows drive letter).
  const picked = givenFile
    ? undefined
    : await vscode.window.showOpenDialog({
        title: "TLS Key Log File (SSLKEYLOGFILE format)",
        openLabel: "Use Key Log File",
        canSelectMany: false,
        defaultUri: start ? vscode.Uri.file(start) : undefined,
        filters: { "Key log files": ["log", "txt", "keys", "keylog"], "All files": ["*"] },
      });
  const file = givenFile ?? picked?.[0]?.fsPath;
  if (!file) {
    return;
  }
  let text: string;
  try {
    text = await readStart(file);
  } catch (err) {
    void vscode.window.showErrorMessage(
      `PCAP Lens: cannot read ${file}: ${(err as Error).message}`,
    );
    return;
  }
  if (!looksLikeKeyLog(text) && givenFile) {
    void vscode.window.showErrorMessage(
      `PCAP Lens: ${path.basename(file)} doesn't look like a TLS key log.`,
    );
    return;
  }
  if (!looksLikeKeyLog(text)) {
    const useIt = "Use It Anyway";
    const choice = await vscode.window.showWarningMessage(
      `${path.basename(file)} doesn't look like a TLS key log.`,
      {
        modal: true,
        detail:
          'Key logs have lines such as "CLIENT_RANDOM <hex> <hex>" or "CLIENT_TRAFFIC_SECRET_0 <hex> <hex>" (set SSLKEYLOGFILE for your browser or curl to get one).',
      },
      useIt,
    );
    if (choice !== useIt) {
      return;
    }
  }
  await updateSetting("tlsKeyLogFile", file, scope);
}

export function registerTlsCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.setTlsKeyLogFile", (args?: unknown) =>
      setTlsKeyLogFile(provider, args),
    ),
  );
}
