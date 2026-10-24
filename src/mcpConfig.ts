/**
 * How to start PCAP Lens's MCP server (`python -m pcap_backend.mcp`, see
 * backend/pcap_backend/mcp.py) and the configuration snippets that tell an AI
 * assistant to: the command line for Claude Code, the `mcpServers` JSON of
 * Claude Desktop, Cursor and others, and VS Code's own `mcp.json`. No
 * `vscode` import: unit-tested.
 */

/** What the server needs to start (paths on the machine where it runs). */
export interface McpLaunch {
  /** The Python interpreter and its leading arguments (`py -3.14` on Windows). */
  python: readonly string[];
  /** The folder holding `pcap_backend` (a stable copy, see commands/mcp.ts). */
  backendDir: string;
  /** Folders whose captures the tools may read (none: the assistant's working folder). */
  roots: readonly string[];
  allowPacketData: boolean;
  standIns: boolean;
  /** pcapViewer.tsharkPath, when set. */
  tsharkPath?: string;
}

export const SERVER_ID = "pcap-lens";

/** The command and arguments that start the server. */
export function serverCommand(l: McpLaunch): { command: string; args: string[] } {
  const [command, ...pythonArgs] = l.python;
  const args = [...pythonArgs, "-m", "pcap_backend.mcp"];
  for (const root of l.roots) {
    args.push("--root", root);
  }
  if (l.allowPacketData) {
    args.push("--allow-packet-data");
  }
  if (l.standIns) {
    args.push("--stand-ins");
  }
  if (l.tsharkPath) {
    args.push("--tshark", l.tsharkPath);
  }
  return { command, args };
}

/** Its environment: Python finds the package through PYTHONPATH. */
export function serverEnv(l: McpLaunch): Record<string, string> {
  return { PYTHONPATH: l.backendDir };
}

/** One argument for a shell: POSIX single quotes, or Windows (PowerShell/cmd) double quotes. */
export function shellQuote(arg: string, windows: boolean): string {
  if (/^[\w@%+=:,./\\-]+$/.test(arg)) {
    return arg;
  }
  return windows ? `"${arg.replace(/"/g, '\\"')}"` : `'${arg.replace(/'/g, "'\\''")}'`;
}

/**
 * `claude mcp add …`: registers the server with Claude Code (user scope).
 * The name comes first: `--env` takes several values and would swallow it;
 * `--` ends them before the command.
 */
export function claudeCodeCommand(l: McpLaunch, windows: boolean): string {
  const { command, args } = serverCommand(l);
  const q = (a: string) => shellQuote(a, windows);
  return [
    `claude mcp add ${SERVER_ID} --scope user`,
    ...Object.entries(serverEnv(l)).map(([k, v]) => `--env ${q(`${k}=${v}`)}`),
    "--",
    q(command),
    ...args.map(q),
  ].join(" ");
}

/** `{"mcpServers": …}`: Claude Desktop, Cursor, Windsurf, Cline and most others. */
export function mcpServersJson(l: McpLaunch): string {
  const { command, args } = serverCommand(l);
  return JSON.stringify(
    { mcpServers: { [SERVER_ID]: { command, args, env: serverEnv(l) } } },
    null,
    2,
  );
}

/** `.vscode/mcp.json` (or the user mcp.json) of VS Code. */
export function vscodeMcpJson(l: McpLaunch): string {
  const { command, args } = serverCommand(l);
  return JSON.stringify(
    { servers: { [SERVER_ID]: { type: "stdio", command, args, env: serverEnv(l) } } },
    null,
    2,
  );
}

export type McpTarget = "claude-code" | "mcp-servers" | "vscode";

export const MCP_TARGETS: readonly { id: McpTarget; label: string; detail: string }[] = [
  {
    id: "claude-code",
    label: "Claude Code",
    detail: "A `claude mcp add` command line to run once in a terminal",
  },
  {
    id: "mcp-servers",
    label: "Claude Desktop, Cursor and others",
    detail: "An `mcpServers` entry for the app's MCP configuration file",
  },
  {
    id: "vscode",
    label: "VS Code mcp.json",
    detail:
      "A `servers` entry for .vscode/mcp.json (not needed in VS Code 1.101+: PCAP Lens adds it)",
  },
];

/** The snippet for `target`. */
export function mcpConfigText(target: McpTarget, l: McpLaunch, windows: boolean): string {
  switch (target) {
    case "claude-code":
      return claudeCodeCommand(l, windows);
    case "mcp-servers":
      return mcpServersJson(l);
    case "vscode":
      return vscodeMcpJson(l);
  }
}
