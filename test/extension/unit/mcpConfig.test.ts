import * as assert from "node:assert/strict";
import {
  MCP_TARGETS,
  McpLaunch,
  claudeCodeCommand,
  mcpConfigText,
  mcpServersJson,
  serverCommand,
  shellQuote,
  vscodeMcpJson,
} from "../../../src/mcpConfig";

const LAUNCH: McpLaunch = {
  python: ["/usr/bin/python3.14"],
  backendDir: "/home/ann/.config/Code/User/globalStorage/denpaz.pcap-viewer/mcp/backend",
  roots: ["/home/ann/captures", "/srv/it's here"],
  allowPacketData: false,
  standIns: true,
};

suite("mcpConfig", () => {
  test("the server's command line follows the settings", () => {
    assert.deepEqual(serverCommand(LAUNCH), {
      command: "/usr/bin/python3.14",
      args: [
        "-m",
        "pcap_backend.mcp",
        "--root",
        "/home/ann/captures",
        "--root",
        "/srv/it's here",
        "--stand-ins",
      ],
    });
    const windows = serverCommand({
      ...LAUNCH,
      python: ["py", "-3.14"],
      roots: [],
      allowPacketData: true,
      standIns: false,
      tsharkPath: "C:\\Program Files\\Wireshark\\tshark.exe",
    });
    assert.deepEqual(windows, {
      command: "py",
      args: [
        "-3.14",
        "-m",
        "pcap_backend.mcp",
        "--allow-packet-data",
        "--tshark",
        "C:\\Program Files\\Wireshark\\tshark.exe",
      ],
    });
  });

  test("shell quoting for the Claude Code command line", () => {
    assert.equal(shellQuote("/usr/bin/python3", false), "/usr/bin/python3");
    assert.equal(shellQuote("it's here", false), "'it'\\''s here'");
    assert.equal(shellQuote("C:\\Program Files\\x", true), '"C:\\Program Files\\x"');
    assert.equal(
      claudeCodeCommand(LAUNCH, false),
      "claude mcp add --scope user --env PYTHONPATH=/home/ann/.config/Code/User/globalStorage/denpaz.pcap-viewer/mcp/backend " +
        "pcap-lens -- /usr/bin/python3.14 -m pcap_backend.mcp --root /home/ann/captures --root '/srv/it'\\''s here' --stand-ins",
    );
  });

  test("JSON for mcpServers apps and VS Code", () => {
    const apps = JSON.parse(mcpServersJson(LAUNCH));
    assert.deepEqual(Object.keys(apps.mcpServers), ["pcap-lens"]);
    assert.equal(apps.mcpServers["pcap-lens"].command, "/usr/bin/python3.14");
    assert.equal(apps.mcpServers["pcap-lens"].env.PYTHONPATH, LAUNCH.backendDir);
    const code = JSON.parse(vscodeMcpJson(LAUNCH));
    assert.equal(code.servers["pcap-lens"].type, "stdio");
    assert.deepEqual(code.servers["pcap-lens"].args, serverCommand(LAUNCH).args);
    for (const t of MCP_TARGETS) {
      assert.ok(mcpConfigText(t.id, LAUNCH, false).includes("pcap_backend.mcp"), t.id);
    }
  });
});
