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
  /** The dissection options file (`dissectionFile`), which VS Code keeps up to date. */
  optionsFile?: string;
  /** Wireshark's own variables the server needs too (`wiresharkEnv`). */
  env?: Record<string, string>;
}

/**
 * The `open` parameters that decide how a capture is dissected, as the
 * server's options file holds them: Lua scripts, Decode As, preferences, the
 * Wireshark profile, protocol and heuristic switches, GeoIP databases. Never
 * decryption keys (VS Code's secret storage keeps them) nor name resolution
 * (the server shows addresses: its rows become address filters).
 */
export interface McpDissection {
  lua?: string[];
  decodeAs?: string[];
  prefs?: Record<string, string | number | boolean>;
  profile?: string;
  protocols?: Record<string, boolean>;
  heuristics?: Record<string, boolean>;
  geoip?: string[];
}

/** A capture's settings as the viewer reads them (config.ts `Settings`). */
interface DissectionSettings {
  luaScripts: readonly string[];
  decodeAs: readonly string[];
  prefs: Record<string, string | number | boolean>;
  wiresharkProfile: string;
  protocols: Record<string, boolean>;
  heuristics: Record<string, boolean>;
  geoipFolders: readonly string[];
}

/** `settings` as options for the server (empty ones left out). */
export function mcpDissection(settings: DissectionSettings): McpDissection {
  const out: McpDissection = {};
  if (settings.luaScripts.length) {
    out.lua = [...settings.luaScripts];
  }
  if (settings.decodeAs.length) {
    out.decodeAs = [...settings.decodeAs];
  }
  if (Object.keys(settings.prefs).length) {
    out.prefs = { ...settings.prefs };
  }
  if (settings.wiresharkProfile) {
    out.profile = settings.wiresharkProfile;
  }
  if (Object.keys(settings.protocols).length) {
    out.protocols = { ...settings.protocols };
  }
  if (Object.keys(settings.heuristics).length) {
    out.heuristics = { ...settings.heuristics };
  }
  if (settings.geoipFolders.length) {
    out.geoip = [...settings.geoipFolders];
  }
  return out;
}

/** What `--options` names: the format the server checks (mcp.py OPTIONS_FORMAT). */
export const DISSECTION_FORMAT = "pcap-lens-dissection";

/**
 * The options file: the settings outside any folder, then each workspace
 * folder's own (the server takes the deepest folder holding a capture), the
 * folders whose options are the default's left out.
 */
export function dissectionFile(
  defaults: McpDissection,
  folders: readonly { root: string; options: McpDissection }[],
): string {
  const same = (a: McpDissection, b: McpDissection) => JSON.stringify(a) === JSON.stringify(b);
  return `${JSON.stringify(
    {
      format: DISSECTION_FORMAT,
      default: defaults,
      folders: folders.filter((f) => !same(f.options, defaults)),
    },
    null,
    2,
  )}\n`;
}

/**
 * Wireshark's variables that change what tshark loads, from VS Code's
 * environment: a plugin folder (compiled and Lua plugins) or a configuration
 * folder set in the shell VS Code started from. An assistant started
 * elsewhere (Claude Desktop, Claude Code from another terminal) wouldn't have
 * them, so the server's configuration carries them.
 */
export const WIRESHARK_VARIABLES = ["WIRESHARK_PLUGIN_DIR", "WIRESHARK_CONFIG_DIR"] as const;

export function wiresharkEnv(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of WIRESHARK_VARIABLES) {
    const value = env[name];
    if (value) {
      out[name] = value;
    }
  }
  return out;
}

export const SERVER_ID = "pcap-lens";

/** The command and arguments that start the server. */
export function serverCommand(l: McpLaunch): { command: string; args: string[] } {
  const [command, ...pythonArgs] = l.python;
  // -P: `-m` would put the working folder (a workspace) first on sys.path, so
  // a folder holding its own pcap_backend would run instead of ours.
  const args = [...pythonArgs, "-P", "-m", "pcap_backend.mcp"];
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
  if (l.optionsFile) {
    args.push("--options", l.optionsFile);
  }
  return { command, args };
}

/** Its environment: Python finds the package through PYTHONPATH; tshark its plugins. */
export function serverEnv(l: McpLaunch): Record<string, string> {
  return { PYTHONPATH: l.backendDir, ...l.env };
}

/**
 * One argument for a shell: POSIX single quotes, or Windows (PowerShell/cmd)
 * double quotes. A Windows program splits its command line by the C runtime's
 * rules: backslashes are literal unless a quote follows, so those before a
 * quote, and before the closing one (`C:\dir\`), are doubled.
 */
export function shellQuote(arg: string, windows: boolean): string {
  if (/^[\w@%+=:,./\\-]+$/.test(arg)) {
    return arg;
  }
  if (!windows) {
    return `'${arg.replace(/'/g, "'\\''")}'`;
  }
  const escaped = arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1");
  return `"${escaped}"`;
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
