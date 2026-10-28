import * as vscode from "vscode";
import { initLuaChoices } from "./luaChoice";
import { registerAnalysisCommands } from "./commands/analysis";
import { registerOpenBerRecordsCommand } from "./commands/openBerRecords";
import { registerOpenFileCommand } from "./commands/openFile";
import { registerPluginCommands } from "./commands/plugins";
import { registerProfileCommands } from "./commands/profiles";
import { registerFirewallCommands } from "./commands/firewall";
import { consumePrefsChange, registerPrefsCommands } from "./commands/prefs";
import { registerProtocolCommands } from "./commands/protocols";
import { keyStore, registerDecryptionCommands } from "./commands/decryption";
import { keysDigest } from "./decryptionKeys";
import { samePrefs } from "./prefsModel";
import { sameSwitches } from "./protocolsModel";
import { registerColoringCommands } from "./commands/coloring";
import { registerColumnCommands } from "./commands/columns";
import { registerDissectorCommands } from "./commands/dissectors";
import { registerExportCommands } from "./commands/export";
import { registerExportPdusCommand } from "./commands/exportPdus";
import { registerReportCommand } from "./commands/report";
import { registerNavigationCommands } from "./commands/navigation";
import { registerFilterCommands } from "./commands/filter";
import { registerSavedFilterCommands } from "./commands/savedFilters";
import { registerFilterButtonCommands } from "./commands/filterButtons";
import {
  COLORING_KEYS,
  RELOAD_KEYS,
  SECTION,
  readColoringStyle,
  readListDensity,
  readQuickDetail,
  readSettings,
} from "./config";
import { FilterAssistant } from "./ai";
import { registerAiCommands } from "./commands/ai";
import { registerIndexCacheCommands } from "./commands/indexCache";
import { registerTlsCommands } from "./commands/tls";
import { registerMergeCommands } from "./commands/merge";
import { registerCommentCommands } from "./commands/comments";
import { registerCaptureCommands } from "./commands/capture";
import { registerMcp } from "./commands/mcp";
import { registerEditCaptureCommands } from "./commands/editCapture";
import { registerImportHexDumpCommand } from "./commands/importHexDump";
import { registerSetupCommands } from "./commands/setup";
import { RecentCapturesProvider, registerRecentCaptures } from "./commands/recent";
import { pruneTemporaryCaptures } from "./tempCaptures";
import { PcapEditorProvider } from "./pcapEditor";
import { ComparePanel } from "./panels/comparePanel";
import { FlowGraphPanel } from "./panels/flowGraphPanel";
import { FollowPanel } from "./panels/followPanel";
import { ObjectsPanel } from "./panels/objectsPanel";
import { ReplayPanel } from "./panels/replayPanel";
import { PacketPanel } from "./panels/packetPanel";
import { StatsPanel } from "./panels/statsPanel";
import { TcpGraphPanel } from "./panels/tcpGraphPanel";
import { VoipPanel } from "./panels/voipPanel";
import { sameNameResolution } from "./settingsModel";

let provider: PcapEditorProvider | undefined;
let namesTimer: ReturnType<typeof setTimeout> | undefined;
let prefsTimer: ReturnType<typeof setTimeout> | undefined;
let switchesTimer: ReturnType<typeof setTimeout> | undefined;

export interface PcapViewerApi {
  /** Exposed for integration tests. */
  readonly provider: PcapEditorProvider;
  readonly recent: RecentCapturesProvider;
  /**
   * The panel classes (their open panels are static fields). The extension
   * runs from the esbuild bundle, so the tests' own imports of these modules
   * would be other instances.
   */
  readonly panels: typeof PANELS;
}

const PANELS = {
  ComparePanel,
  FlowGraphPanel,
  FollowPanel,
  ObjectsPanel,
  PacketPanel,
  ReplayPanel,
  StatsPanel,
  TcpGraphPanel,
  VoipPanel,
};

export function activate(context: vscode.ExtensionContext): PcapViewerApi {
  // Before any capture loads: readSettings applies each capture's Lua choice.
  initLuaChoices(context.workspaceState);
  const log = vscode.window.createOutputChannel("PCAP Lens", { log: true });
  context.subscriptions.push(log);
  const assistant = new FilterAssistant(log);
  context.subscriptions.push(assistant);
  provider = PcapEditorProvider.register(context, log, assistant);
  const p = provider;
  // (Starts loading the keys; a capture's load waits for them.)
  registerDecryptionCommands(context, p);

  registerFilterCommands(context, p);
  registerColumnCommands(context, p);
  registerSavedFilterCommands(context, p);
  registerFilterButtonCommands(context, p);
  registerAnalysisCommands(context, p);
  registerDissectorCommands(context, p, log, assistant);
  registerExportCommands(context, p);
  registerExportPdusCommand(context, p, log);
  registerReportCommand(context, p, log);
  registerNavigationCommands(context, p);
  registerColoringCommands(context, p);
  registerAiCommands(context, p, log);
  registerMcp(context, log);
  registerIndexCacheCommands(context);
  registerTlsCommands(context, p);
  registerMergeCommands(context, p, log);
  registerCommentCommands(context, p);
  registerCaptureCommands(context, p, log, assistant);
  registerEditCaptureCommands(context, p, log);
  registerImportHexDumpCommand(context, p, log);
  registerOpenFileCommand(context, p, log);
  registerOpenBerRecordsCommand(context, p, log);
  registerPluginCommands(context, p, log);
  registerProfileCommands(context, p, log);
  registerFirewallCommands(context, p);
  registerPrefsCommands(context, p, log);
  registerProtocolCommands(context, p, log);
  registerSetupCommands(context, log);
  const recent = registerRecentCaptures(context);
  context.subscriptions.push(
    keyStore.onDidChange(() => {
      // PCAP: Decryption Keys… (here or in another window): reload the captures
      // loaded with other keys.
      const keys = keysDigest(keyStore.all);
      for (const s of p.allSessions.filter((s) => s.keys !== keys)) {
        void s.load("decryption keys changed");
      }
    }),
  );
  // Unsaved captures left behind (a crash, or a restored editor long closed).
  void pruneTemporaryCaptures(context, new Set(p.allSessions.map((s) => s.uri.fsPath)));
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.showLog", () => log.show()),
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (!e.affectsConfiguration(SECTION)) {
        return;
      }
      if (
        e.affectsConfiguration(`${SECTION}.columns`) ||
        e.affectsConfiguration(`${SECTION}.columnLayout`)
      ) {
        for (const s of p.allSessions) {
          const settings = readSettings(s.uri); // folder-scoped: each capture its own
          s.setColumns(settings.columns, settings.columnLayout);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.timeFormat`)) {
        for (const s of p.allSessions) {
          s.setTimeFormat(readSettings(s.uri).timeFormat);
        }
      }
      if (
        e.affectsConfiguration(`${SECTION}.quickDetail`) ||
        e.affectsConfiguration(`${SECTION}.twoPassDetail`)
      ) {
        for (const s of p.allSessions) {
          s.setQuickDetail(readQuickDetail(s.uri));
        }
      }
      if (e.affectsConfiguration(`${SECTION}.coloringStyle`)) {
        for (const s of p.allSessions) {
          s.setColoringStyle(readColoringStyle(s.uri));
        }
      }
      if (e.affectsConfiguration(`${SECTION}.listDensity`)) {
        for (const s of p.allSessions) {
          s.setListDensity(readListDensity(s.uri));
        }
      }
      if (e.affectsConfiguration(`${SECTION}.filterButtons`)) {
        const buttons = readSettings().filterButtons;
        for (const s of p.allSessions) {
          s.setFilterButtons(buttons);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.savedFilters`)) {
        const saved = readSettings().savedFilters;
        for (const s of p.allSessions) {
          s.setSavedFilters(saved);
        }
      }
      if (COLORING_KEYS.some((k) => e.affectsConfiguration(k))) {
        // Colors are re-evaluated in the background; no re-indexing needed.
        for (const s of p.allSessions) {
          void s.applyColoring();
        }
      }
      if (e.affectsConfiguration(`${SECTION}.nameResolution`)) {
        // Usually PCAP: Name Resolution…, which can change several keys: reload
        // once they are all written (saved indexes make switching back instant).
        clearTimeout(namesTimer);
        namesTimer = setTimeout(() => {
          for (const s of p.allSessions.filter(
            (s) => !sameNameResolution(readSettings(s.uri).nameResolution, s.names),
          )) {
            void s.load("name resolution changed");
          }
        }, 300);
      }
      if (e.affectsConfiguration(`${SECTION}.wiresharkProfile`)) {
        // Usually PCAP: Use Wireshark Profile…: reload the captures it changes.
        await Promise.all(
          p.allSessions
            .filter((s) => readSettings(s.uri).wiresharkProfile !== s.wiresharkProfile)
            .map((s) => s.load("Wireshark profile changed")),
        );
      }
      if (
        e.affectsConfiguration(`${SECTION}.enabledProtocols`) ||
        e.affectsConfiguration(`${SECTION}.heuristicDissectors`)
      ) {
        // PCAP: Enabled Protocols… (both keys, one after the other) or Disable
        // Protocol: reload the captures whose switches changed.
        clearTimeout(switchesTimer);
        switchesTimer = setTimeout(() => {
          for (const s of p.allSessions) {
            const settings = readSettings(s.uri);
            if (
              !sameSwitches(settings.protocols, s.protocols) ||
              !sameSwitches(settings.heuristics, s.heuristics)
            ) {
              void s.load("enabled protocols changed");
            }
          }
        }, 300);
      }
      if (e.affectsConfiguration(`${SECTION}.geoip.databaseFolders`)) {
        await Promise.all(
          p.allSessions
            .filter(
              (s) => readSettings(s.uri).geoipFolders.join("\n") !== s.geoipFolders.join("\n"),
            )
            .map((s) => s.load("GeoIP databases changed")),
        );
      }
      if (e.affectsConfiguration(`${SECTION}.tlsKeyLogFile`)) {
        // Usually PCAP: Set TLS Key Log File…: reload the captures whose key log changed.
        await Promise.all(
          p.allSessions
            .filter((s) => readSettings(s.uri).tlsKeyLogFile !== s.keyLogFile)
            .map((s) => s.load("TLS key log setting changed")),
        );
      }
      if (e.affectsConfiguration(`${SECTION}.prefs`) && consumePrefsChange()) {
        // PCAP: Protocol Preferences…: reload the captures whose preferences
        // changed, without asking (debounced: several changes in a row).
        clearTimeout(prefsTimer);
        prefsTimer = setTimeout(() => {
          for (const s of p.allSessions.filter(
            (s) => !samePrefs(readSettings(s.uri).prefs, s.prefs),
          )) {
            void s.load("protocol preferences changed");
          }
        }, 300);
        return;
      }
      if (RELOAD_KEYS.some((k) => e.affectsConfiguration(k)) && p.allSessions.length) {
        const choice = await vscode.window.showInformationMessage(
          "PCAP Lens settings changed. Reload open captures to apply them?",
          "Reload",
        );
        if (choice === "Reload") {
          await Promise.all(p.allSessions.map((s) => s.load("settings changed")));
        }
      }
    }),
  );
  return { provider: p, recent, panels: PANELS };
}

export async function deactivate(): Promise<void> {
  // Make sure no python/tshark process outlives the extension host.
  await provider?.disposeAll();
  provider = undefined;
}
