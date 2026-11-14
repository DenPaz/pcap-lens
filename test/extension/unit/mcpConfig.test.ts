import * as assert from "node:assert/strict";
import {
  DISSECTION_FORMAT,
  MCP_TARGETS,
  McpLaunch,
  claudeCodeCommand,
  dissectionFile,
  dissectionFileName,
  mcpConfigText,
  mcpDissection,
  mcpServersJson,
  serverCommand,
  serverEnv,
  shellQuote,
  vscodeMcpJson,
  wiresharkEnv,
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
        "-P",
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
        "-P",
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
    // The C runtime's rules: backslashes double only before a quote.
    assert.equal(shellQuote("C:\\My Dir\\", true), '"C:\\My Dir\\\\"');
    assert.equal(shellQuote('say \\"hi"', true), '"say \\\\\\"hi\\""');
    assert.equal(shellQuote('a\\\\"b\\ c\\\\', true), '"a\\\\\\\\\\"b\\ c\\\\\\\\"');
    // The same quoting as the regexes it replaced, on every short string of
    // these characters…
    const before = (arg: string): string =>
      `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
    const strings = (n: number): string[] =>
      n === 0 ? [""] : strings(n - 1).flatMap((p) => ["\\", '"', "a", " "].map((c) => p + c));
    for (let n = 1; n <= 6; n++) {
      for (const arg of strings(n).filter((a) => !/^[\w@%+=:,./\\-]+$/.test(a))) {
        assert.equal(shellQuote(arg, true), before(arg), JSON.stringify(arg));
      }
    }
    // …in linear time: a long run of backslashes took quadratic time.
    const started = Date.now();
    assert.equal(shellQuote(" " + "\\".repeat(100000) + "x", true).length, 100004);
    assert.ok(Date.now() - started < 500, "linear time");
    assert.equal(
      claudeCodeCommand(LAUNCH, false),
      "claude mcp add pcap-lens --scope user --env PYTHONPATH=/home/ann/.config/Code/User/globalStorage/denpaz.pcap-viewer/mcp/backend " +
        "-- /usr/bin/python3.14 -P -m pcap_backend.mcp --root /home/ann/captures --root '/srv/it'\\''s here' --stand-ins",
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

  test("the dissection options and Wireshark's variables reach the server", () => {
    const l: McpLaunch = {
      ...LAUNCH,
      optionsFile: "/home/ann/.config/Code/User/globalStorage/x/mcp/dissection.json",
      env: { WIRESHARK_PLUGIN_DIR: "/opt/li/plugins" },
    };
    assert.deepEqual(serverCommand(l).args.slice(-2), ["--options", l.optionsFile]);
    assert.deepEqual(serverEnv(l), {
      WIRESHARK_PLUGIN_DIR: "/opt/li/plugins",
      PYTHONPATH: LAUNCH.backendDir,
    });
    assert.ok(
      claudeCodeCommand(l, false).includes("--env WIRESHARK_PLUGIN_DIR=/opt/li/plugins "),
      "a pasted configuration carries them too",
    );
    assert.deepEqual(
      wiresharkEnv({ WIRESHARK_PLUGIN_DIR: "/p", WIRESHARK_CONFIG_DIR: "", PATH: "/bin" }),
      { WIRESHARK_PLUGIN_DIR: "/p" },
    );
  });

  test("dissection options from the settings, per workspace folder", () => {
    const none = {
      luaScripts: [],
      decodeAs: [],
      prefs: {},
      wiresharkProfile: "",
      protocols: {},
      heuristics: {},
      geoipFolders: [],
    };
    assert.deepEqual(mcpDissection(none), {});
    const li = mcpDissection({
      ...none,
      luaScripts: ["/work/li/hi2.lua"],
      decodeAs: ["tcp.port==11001,hi2"],
      prefs: { "tls.keylog_file": "/work/keys.log" },
      wiresharkProfile: "LI",
      protocols: { sip: false },
    });
    assert.deepEqual(li, {
      lua: ["/work/li/hi2.lua"],
      decodeAs: ["tcp.port==11001,hi2"],
      prefs: { "tls.keylog_file": "/work/keys.log" },
      profile: "LI",
      protocols: { sip: false },
    });
    const file = JSON.parse(
      dissectionFile({}, [
        { root: "/work/li", options: li },
        { root: "/work/other", options: {} },
      ]),
    );
    assert.equal(file.format, DISSECTION_FORMAT);
    assert.deepEqual(file.default, {});
    assert.deepEqual(
      file.folders,
      [{ root: "/work/li", options: li }],
      "same as default: left out",
    );
  });

  test("dissectionFile keeps a folder that overrides its outer folder, even with the defaults", () => {
    const decode = { decodeAs: ["udp.port==9999,syslog"] };
    const file = (folders: { root: string; options: object }[]) =>
      JSON.parse(dissectionFile({}, folders)).folders.map((f: { root: string }) => f.root);
    // The inner folder uses the defaults inside an outer one that doesn't: kept,
    // else the server would take the outer folder's options for its captures.
    assert.deepEqual(
      file([
        { root: "/work/outer/inner", options: {} },
        { root: "/work/outer", options: decode },
        { root: "/work/outer-not-inside", options: {} },
      ]),
      ["/work/outer/inner", "/work/outer"],
    );
    // An inner folder with its outer folder's options adds nothing; Windows paths too.
    assert.deepEqual(
      file([
        { root: "C:\\work\\outer", options: decode },
        { root: "C:\\work\\outer\\inner", options: decode },
        { root: "C:\\work\\outer\\inner\\deeper", options: {} },
      ]),
      ["C:\\work\\outer", "C:\\work\\outer\\inner\\deeper"],
    );
  });

  test("dissectionFileName: one file per workspace", () => {
    assert.equal(dissectionFileName([]), "dissection.json");
    const a = dissectionFileName(["file:///work/a"]);
    assert.match(a, /^dissection-[0-9a-f]{16}\.json$/);
    assert.equal(dissectionFileName(["file:///work/a"]), a);
    assert.notEqual(dissectionFileName(["file:///work/b"]), a);
    assert.notEqual(dissectionFileName(["file:///work/a", "file:///work/b"]), a);
  });
});
