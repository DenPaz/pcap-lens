import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import {
  ProtocolListing,
  Switches,
  effectiveSwitch,
  switchDescription,
  switchOverrides,
} from "../protocolsModel";
import { withBackend } from "./withBackend";

const RESET_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("discard"),
  tooltip: "Use Wireshark's settings (drop every change made here)",
};

type Row = vscode.QuickPickItem & { name?: string; heuristic?: boolean };

/** Arguments of `pcapViewer.enabledProtocols` (smoke test, scripts). */
interface EnabledProtocolsArgs {
  /** Return the listing and show nothing. */
  quiet?: boolean;
  /** Store these overrides without asking (`{}` clears them). */
  protocols?: Switches;
  heuristics?: Switches;
}

/**
 * _PCAP: Enabled Protocols…_ (Wireshark's Analyze → Enabled Protocols): every
 * protocol and heuristic dissector tshark can switch, checked when on for the
 * active capture. Accepting stores what differs from Wireshark's own settings
 * in `pcapViewer.enabledProtocols` / `pcapViewer.heuristicDissectors` for
 * the capture's folder; extension.ts reloads the captures it changes.
 * _Disable Protocol_ (the packet details' menu) switches one off at once.
 */
export function registerProtocolCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  const listing = () =>
    withBackend(provider, context, log, (backend) =>
      backend.request<ProtocolListing>("enabled_protocols", {}, { timeoutMs: 60_000 }),
    );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pcapViewer.enabledProtocols",
      async (args?: EnabledProtocolsArgs): Promise<unknown> => {
        const scope = provider.activeSession?.uri;
        try {
          if (args?.protocols || args?.heuristics) {
            await store(scope, args.protocols, args.heuristics);
            return { protocols: args.protocols, heuristics: args.heuristics };
          }
          const listed = await listing();
          if (args?.quiet) {
            return listed;
          }
          await pickSwitches(listed, scope);
        } catch (err) {
          void vscode.window.showErrorMessage(
            `PCAP Lens: enabled protocols: ${describeError(err)}`,
          );
        }
        return undefined;
      },
    ),
    vscode.commands.registerCommand(
      "pcapViewer.disableProtocol",
      async (args?: { protocol?: unknown }): Promise<void> => {
        const protocol = typeof args?.protocol === "string" ? args.protocol : "";
        const scope = provider.activeSession?.uri;
        try {
          const listed = await listing();
          const p = listed.protocols.find((x) => x.name === protocol);
          if (!p) {
            void vscode.window.showInformationMessage(
              `${protocol || "This protocol"} can't be switched off.`,
            );
            return;
          }
          const before = readSettings(scope).protocols;
          await store(scope, { ...before, [p.name]: false }, undefined);
          const choice = await vscode.window.showInformationMessage(
            `Disabled ${p.short} (${p.name}) for this capture's folder.`,
            "Undo",
            "Enabled Protocols…",
          );
          if (choice === "Undo") {
            await store(scope, before, undefined);
          } else if (choice === "Enabled Protocols…") {
            await pickSwitches(await listing(), scope);
          }
        } catch (err) {
          void vscode.window.showErrorMessage(`PCAP Lens: disable protocol: ${describeError(err)}`);
        }
      },
    ),
  );
}

async function store(
  scope: vscode.Uri | undefined,
  protocols: Switches | undefined,
  heuristics: Switches | undefined,
): Promise<void> {
  const value = (s: Switches) => (Object.keys(s).length ? s : undefined);
  if (protocols) {
    await updateSetting("enabledProtocols", value(protocols), scope);
  }
  if (heuristics) {
    await updateSetting("heuristicDissectors", value(heuristics), scope);
  }
}

async function pickSwitches(listed: ProtocolListing, scope: vscode.Uri | undefined): Promise<void> {
  const settings = readSettings(scope);
  const rows: Row[] = [];
  const on: Row[] = [];
  const add = (row: Row, enabled: boolean) => {
    rows.push(row);
    if (enabled) {
      on.push(row);
    }
  };
  rows.push({ label: "Protocols", kind: vscode.QuickPickItemKind.Separator });
  for (const p of listed.protocols) {
    const state = effectiveSwitch(
      p.name,
      p.default,
      listed.wireshark.protocols,
      settings.protocols,
    );
    add(
      {
        label: p.short,
        description: `${p.title === p.short ? "" : `${p.title} · `}${switchDescription(p.name, state.source, state.on)}`,
        name: p.name,
      },
      state.on,
    );
  }
  rows.push({ label: "Heuristic dissectors", kind: vscode.QuickPickItemKind.Separator });
  for (const h of listed.heuristics) {
    const state = effectiveSwitch(
      h.name,
      h.default,
      listed.wireshark.heuristics,
      settings.heuristics,
    );
    add(
      {
        label: h.title,
        description: switchDescription(h.name, state.source, state.on),
        name: h.name,
        heuristic: true,
      },
      state.on,
    );
  }
  const qp = vscode.window.createQuickPick<Row>();
  qp.title = "Enabled Protocols";
  qp.placeholder = "Check the protocols and heuristic dissectors tshark should use";
  qp.canSelectMany = true;
  qp.matchOnDescription = true;
  qp.items = rows;
  qp.selectedItems = on;
  qp.buttons = [RESET_BUTTON];
  const result = await new Promise<"accept" | "reset" | undefined>((resolve) => {
    qp.onDidTriggerButton(() => {
      resolve("reset");
      qp.hide();
    });
    qp.onDidAccept(() => {
      resolve("accept");
      qp.hide();
    });
    qp.onDidHide(() => resolve(undefined));
    qp.show();
  });
  const chosen = qp.selectedItems;
  qp.dispose();
  if (result === "reset") {
    await store(scope, {}, {});
  } else if (result === "accept") {
    const names = (heuristic: boolean) =>
      new Set(chosen.filter((r) => !!r.heuristic === heuristic && r.name).map((r) => r.name!));
    await store(
      scope,
      switchOverrides(
        listed.protocols,
        listed.wireshark.protocols,
        settings.protocols,
        names(false),
      ),
      switchOverrides(
        listed.heuristics,
        listed.wireshark.heuristics,
        settings.heuristics,
        names(true),
      ),
    );
  }
}
