import * as vscode from "vscode";
import { BackendClient, MIN_PYTHON, findPython, findUv } from "../backendClient";
import { readSettings } from "../config";
import {
  EnvironmentStatus,
  checkEnvironment,
  environmentSummary,
  settingToFix,
} from "../environment";
import { copyName, whereLabel } from "../remote";
import { newTemporaryCapture } from "../tempCaptures";

/** The Get Started walkthrough's id in package.json. */
export const WALKTHROUGH = "gettingStarted";
/** Context keys the walkthrough's Python and TShark steps complete on. */
export const PYTHON_FOUND = "pcapViewer.pythonFound";
export const TSHARK_FOUND = "pcapViewer.tsharkFound";
/** …the Open step, once a capture loaded, and the Filter step, once a filter was applied. */
export const CAPTURE_OPENED = "pcapViewer.captureOpened";
export const FILTER_APPLIED = "pcapViewer.filterApplied";

const DOWNLOADS = {
  pythonPath: "https://www.python.org/downloads/",
  tsharkPath: "https://www.wireshark.org/download.html",
} as const;
const UV_INSTALL = "https://docs.astral.sh/uv/getting-started/installation/";
/** The Python that _PCAP: Install Python…_ installs with uv (any >= MIN_PYTHON works). */
export const RECOMMENDED_PYTHON = "3.14";
/** The task type of that install (package.json `taskDefinitions`). */
const INSTALL_TASK_TYPE = "pcapViewer.installPython";

/** Mark the walkthrough's setup steps done (a capture that loads proves both). */
export function setEnvironmentContext(python: boolean, tshark: boolean): void {
  void vscode.commands.executeCommand("setContext", PYTHON_FOUND, python);
  void vscode.commands.executeCommand("setContext", TSHARK_FOUND, tshark);
}

export function openWalkthrough(context: vscode.ExtensionContext): Thenable<unknown> {
  return vscode.commands.executeCommand(
    "workbench.action.openWalkthrough",
    `${context.extension.id}#${WALKTHROUGH}`,
    false,
  );
}

/** Offer the fixes for a missing Python or tshark (also used when a capture can't load). */
export async function offerSetupHelp(
  context: vscode.ExtensionContext,
  message: string,
  setting: "pythonPath" | "tsharkPath",
): Promise<void> {
  const download = setting === "pythonPath" ? "Install Python…" : "Download Wireshark";
  // Remotely, the tools must be on the remote machine (the download page opens locally).
  const where = whereLabel(vscode.env.remoteName);
  const text =
    where && !message.includes(where)
      ? `${message} PCAP Lens runs in ${where}: install it there.`
      : message;
  const choice = await vscode.window.showErrorMessage(
    `PCAP Lens: ${text}`,
    "Setup Guide",
    download,
    "Open Settings",
  );
  if (choice === "Setup Guide") {
    await openWalkthrough(context);
  } else if (choice === download) {
    if (setting === "pythonPath") {
      await vscode.commands.executeCommand("pcapViewer.installPython");
    } else {
      await vscode.env.openExternal(vscode.Uri.parse(DOWNLOADS[setting]));
    }
  } else if (choice === "Open Settings") {
    await vscode.commands.executeCommand("workbench.action.openSettings", `pcapViewer.${setting}`);
  }
}

/**
 * _PCAP: Install Python…_: with uv installed, run `uv python install` as a
 * task (a process, no shell; in a remote window it runs on the remote
 * machine, where the backend runs) and check the environment again when it
 * succeeds. Without uv, point to python.org and to uv's installation page:
 * an extension shouldn't pipe an install script from the internet into a shell.
 */
export async function installPython(): Promise<void> {
  const uv = findUv();
  if (!uv) {
    const choice = await vscode.window.showInformationMessage(
      `PCAP Lens needs Python ${MIN_PYTHON.join(".")} or newer. Install it from python.org, ` +
        `or install uv, then run this command again: uv installs Python ${RECOMMENDED_PYTHON} without admin rights.`,
      "Download Python",
      "Install uv",
    );
    if (choice === "Download Python") {
      await vscode.env.openExternal(vscode.Uri.parse(DOWNLOADS.pythonPath));
    } else if (choice === "Install uv") {
      await vscode.env.openExternal(vscode.Uri.parse(UV_INSTALL));
    }
    return;
  }
  const task = new vscode.Task(
    { type: INSTALL_TASK_TYPE },
    vscode.TaskScope.Global,
    `Install Python ${RECOMMENDED_PYTHON}`,
    "PCAP Lens",
    new vscode.ProcessExecution(uv, ["python", "install", RECOMMENDED_PYTHON]),
  );
  task.presentationOptions = { reveal: vscode.TaskRevealKind.Always, clear: true };
  const execution = await vscode.tasks.executeTask(task);
  const done = vscode.tasks.onDidEndTaskProcess((e) => {
    if (e.execution !== execution) {
      return;
    }
    done.dispose();
    if (e.exitCode === 0) {
      void vscode.commands.executeCommand("pcapViewer.checkEnvironment");
    } else {
      void vscode.window.showErrorMessage(
        `PCAP Lens: installing Python with uv failed (exit code ${e.exitCode}); see the terminal.`,
      );
    }
  });
}

/**
 * Open a copy of a capture that isn't a file on disk (Live Share, archives,
 * virtual file systems) as an unsaved capture. Returns the copy.
 */
export async function openCopy(
  context: vscode.ExtensionContext,
  uri: vscode.Uri,
): Promise<vscode.Uri> {
  const data = await vscode.workspace.fs.readFile(uri);
  const copy = vscode.Uri.file(await newTemporaryCapture(context, copyName(uri)));
  await vscode.workspace.fs.writeFile(copy, data);
  await vscode.commands.executeCommand("vscode.openWith", copy, "pcapViewer.editor");
  return copy;
}

export function registerSetupCommands(
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
): void {
  const backendDir = vscode.Uri.joinPath(context.extensionUri, "backend").fsPath;

  async function initialize(python: string[], tsharkPath: string | undefined) {
    const client = new BackendClient({
      python,
      backendDir,
      logger: { info: (m) => log.info(m), warn: (m) => log.warn(m), error: (m) => log.error(m) },
    });
    try {
      client.start();
      return await client.request<{ version: string; tsharkPath: string }>(
        "initialize",
        { tsharkPath },
        { timeoutMs: 30_000 },
      );
    } finally {
      await client.dispose();
    }
  }

  context.subscriptions.push(
    /** Returns the status (the smoke test reads it); `{quiet: true}` shows no message. */
    vscode.commands.registerCommand(
      "pcapViewer.checkEnvironment",
      async (options?: { quiet?: boolean }): Promise<EnvironmentStatus> => {
        const status = await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Window, title: "PCAP: Checking Python and TShark…" },
          () => checkEnvironment(readSettings(), { findPython, initialize }),
        );
        setEnvironmentContext(status.python.ok, status.tshark.ok);
        const summary = environmentSummary(status, whereLabel(vscode.env.remoteName));
        const fix = settingToFix(status);
        (fix ? log.warn : log.info).call(log, `environment check: ${summary}`);
        if (!options?.quiet) {
          if (fix) {
            void offerSetupHelp(context, summary, fix);
          } else {
            void vscode.window.showInformationMessage(`PCAP Lens: ${summary}`);
          }
        }
        return status;
      },
    ),
    vscode.commands.registerCommand("pcapViewer.installPython", installPython),
    vscode.commands.registerCommand("pcapViewer.openSample", async () => {
      // A copy in the extension's storage: comments saved into it must not
      // touch the installed extension (which updates replace anyway).
      // A file: URI (tshark reads files): globalStorageUri itself can be
      // vscode-userdata:, which the viewer would offer to copy instead.
      const dir = vscode.Uri.joinPath(vscode.Uri.file(context.globalStorageUri.fsPath), "samples");
      const sample = vscode.Uri.joinPath(dir, "sample.pcapng");
      await vscode.workspace.fs.createDirectory(dir);
      try {
        await vscode.workspace.fs.stat(sample);
      } catch {
        await vscode.workspace.fs.copy(
          vscode.Uri.joinPath(context.extensionUri, "media", "sample.pcapng"),
          sample,
        );
      }
      await vscode.commands.executeCommand("vscode.openWith", sample, "pcapViewer.editor");
      return sample;
    }),
    vscode.commands.registerCommand("pcapViewer.openWalkthrough", () => openWalkthrough(context)),
    // (the "Open a Copy" button of a capture that isn't on disk; not in the palette)
    vscode.commands.registerCommand("pcapViewer.openCopy", (uri: vscode.Uri) =>
      openCopy(context, uri),
    ),
  );
}
