import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { findPython } from "../backendClient";
import { SECTION, readSettings } from "../config";
import {
  MCP_TARGETS,
  McpLaunch,
  McpTarget,
  mcpConfigText,
  serverCommand,
  serverEnv,
} from "../mcpConfig";
import { whereLabel } from "../remote";

/**
 * PCAP Lens's MCP server for AI assistants (backend/pcap_backend/mcp.py):
 * VS Code 1.101+ gets it through `lm.registerMcpServerDefinitionProvider`
 * (agent mode lists it; detected at run time, as engines.vscode is 1.90), and
 * _PCAP: Copy MCP Server Configuration…_ gives the snippet other assistants
 * need. Both start Python on a stable copy of the backend
 * (`globalStorage/mcp/backend`), refreshed when the extension's version
 * changes, so a configuration pasted elsewhere survives updates.
 */

interface McpProvider {
  onDidChangeMcpServerDefinitions?: vscode.Event<void>;
  provideMcpServerDefinitions(token: vscode.CancellationToken): unknown[];
}

interface McpApi {
  registerMcpServerDefinitionProvider(id: string, provider: McpProvider): vscode.Disposable;
}

type StdioDefinition = new (
  label: string,
  command: string,
  args?: string[],
  env?: Record<string, string>,
  version?: string,
) => { cwd?: vscode.Uri };

/** VS Code's MCP API, or undefined before 1.101. */
function mcpApi(): { api: McpApi; Stdio: StdioDefinition } | undefined {
  const api = vscode.lm as unknown as Partial<McpApi> | undefined;
  const Stdio = (vscode as unknown as Record<string, unknown>).McpStdioServerDefinition as
    StdioDefinition | undefined;
  return typeof api?.registerMcpServerDefinitionProvider === "function" && Stdio
    ? { api: api as McpApi, Stdio }
    : undefined;
}

const VERSION_FILE = ".pcap-lens-version";

/**
 * The backend copy the MCP server runs from: copied from the extension when
 * its version (or, while developing, anything) may have changed.
 */
export function stableBackend(context: vscode.ExtensionContext): string {
  const dir = path.join(context.globalStorageUri.fsPath, "mcp", "backend");
  const version = String(context.extension.packageJSON.version ?? "");
  const develop = context.extensionMode !== vscode.ExtensionMode.Production;
  try {
    if (!develop && fs.readFileSync(path.join(dir, VERSION_FILE), "utf8") === version) {
      return dir;
    }
  } catch {
    // (no copy yet)
  }
  const tmp = `${dir}.${process.pid}.tmp`;
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  fs.cpSync(
    path.join(context.extensionUri.fsPath, "backend", "pcap_backend"),
    path.join(tmp, "pcap_backend"),
    { recursive: true, filter: (src) => path.basename(src) !== "__pycache__" },
  );
  fs.writeFileSync(path.join(tmp, VERSION_FILE), version);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.renameSync(tmp, dir);
  return dir;
}

const mcpSetting = <T>(key: string, fallback: T): T =>
  vscode.workspace.getConfiguration(SECTION).get<T>(key, fallback);

function workspaceRoots(): string[] {
  return (vscode.workspace.workspaceFolders ?? [])
    .filter((f) => f.uri.scheme === "file")
    .map((f) => f.uri.fsPath);
}

/** How to start the server with the current settings, or why it can't start. */
function launch(context: vscode.ExtensionContext, roots: string[]): McpLaunch | { error: string } {
  const settings = readSettings();
  const py = findPython(settings.pythonPath || undefined);
  if ("error" in py) {
    return { error: py.error };
  }
  let backendDir: string;
  try {
    backendDir = stableBackend(context);
  } catch (err) {
    return { error: `Couldn't copy the backend for the MCP server: ${(err as Error).message}` };
  }
  return {
    python: py.python,
    backendDir,
    roots,
    allowPacketData: mcpSetting("mcp.allowPacketData", false),
    standIns: mcpSetting("ai.pseudonymizeAddresses", true),
    tsharkPath: settings.tsharkPath || undefined,
  };
}

/** VS Code's agent mode: the server, reading the workspace folders (else the home folder). */
function registerProvider(context: vscode.ExtensionContext, log: vscode.LogOutputChannel): void {
  const found = mcpApi();
  if (!found) {
    log.info("MCP server definitions need VS Code 1.101+: not registered");
    return;
  }
  const changed = new vscode.EventEmitter<void>();
  const version = String(context.extension.packageJSON.version ?? "");
  context.subscriptions.push(
    changed,
    found.api.registerMcpServerDefinitionProvider("pcapViewer.mcp", {
      onDidChangeMcpServerDefinitions: changed.event,
      provideMcpServerDefinitions: () => {
        if (!mcpSetting("mcp.enabled", true)) {
          return [];
        }
        const roots = workspaceRoots();
        const l = launch(context, roots.length ? roots : [os.homedir()]);
        if ("error" in l) {
          log.warn(`MCP server not offered: ${l.error}`);
          return [];
        }
        const { command, args } = serverCommand(l);
        // (The version changes with the arguments, so VS Code restarts the server.)
        const definition = new found.Stdio(
          "PCAP Lens",
          command,
          args,
          serverEnv(l),
          `${version}+${createHash("sha256")
            .update(JSON.stringify([command, args]))
            .digest("hex")
            .slice(0, 8)}`,
        );
        definition.cwd = vscode.Uri.file(l.roots[0]);
        return [definition];
      },
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration(`${SECTION}.mcp`) ||
        e.affectsConfiguration(`${SECTION}.ai.pseudonymizeAddresses`) ||
        e.affectsConfiguration(`${SECTION}.pythonPath`) ||
        e.affectsConfiguration(`${SECTION}.tsharkPath`)
      ) {
        changed.fire();
      }
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => changed.fire()),
  );
}

interface CopyArgs {
  target?: McpTarget;
  /** Return the text instead of copying it (smoke test). */
  quiet?: boolean;
}

/** "PCAP: Copy MCP Server Configuration…": the snippet for an assistant, on the clipboard. */
async function copyMcpConfig(
  context: vscode.ExtensionContext,
  args?: CopyArgs,
): Promise<string | undefined> {
  let target = MCP_TARGETS.find((t) => t.id === args?.target)?.id;
  if (!target) {
    const pick = await vscode.window.showQuickPick(
      MCP_TARGETS.map((t) => ({ label: t.label, detail: t.detail, id: t.id })),
      {
        title: "Copy MCP Server Configuration",
        placeHolder: "Which assistant should use PCAP Lens's capture tools?",
      },
    );
    if (!pick) {
      return undefined;
    }
    target = pick.id;
  }
  // (Claude Code reads its working folder when no folder is named.)
  const roots = workspaceRoots();
  const l = launch(context, target === "claude-code" && !roots.length ? [] : roots);
  if ("error" in l) {
    void vscode.window.showErrorMessage(`PCAP Lens: ${l.error}`);
    return undefined;
  }
  const text = mcpConfigText(target, l, process.platform === "win32");
  if (args?.quiet) {
    return text;
  }
  await vscode.env.clipboard.writeText(text);
  const label = MCP_TARGETS.find((t) => t.id === target)?.label ?? target;
  const where = whereLabel(vscode.env.remoteName);
  const show = "Show";
  const settings = "Settings";
  const choice = await vscode.window.showInformationMessage(
    `Copied the MCP server configuration for ${label}.` +
      (target === "claude-code"
        ? " Run it once in a terminal."
        : " Paste it into the app's MCP configuration.") +
      (l.roots.length ? ` It may read captures in ${l.roots.join(", ")}.` : "") +
      (where ? ` Its paths are on ${where}: the assistant must run there.` : ""),
    show,
    settings,
  );
  if (choice === show) {
    const doc = await vscode.workspace.openTextDocument({
      language: target === "claude-code" ? "shellscript" : "json",
      content: text,
    });
    await vscode.window.showTextDocument(doc);
  } else if (choice === settings) {
    await vscode.commands.executeCommand("workbench.action.openSettings", `${SECTION}.mcp`);
  }
  return text;
}

export function registerMcp(context: vscode.ExtensionContext, log: vscode.LogOutputChannel): void {
  registerProvider(context, log);
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.copyMcpConfig", (args?: CopyArgs) =>
      copyMcpConfig(context, args),
    ),
  );
}
