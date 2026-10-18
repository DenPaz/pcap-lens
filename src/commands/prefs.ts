import * as vscode from "vscode";
import type { BackendClient } from "../backendClient";
import { getSetting, updateSetting } from "../config";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import {
  PrefOverrides,
  ProtocolPref,
  effectivePref,
  prefLabel,
  prefSettingValue,
  samePrefs,
  sameValue,
  validatePrefValue,
  withPref,
} from "../prefsModel";
import { withBackend } from "./withBackend";

/** Set while this command writes pcapViewer.prefs: it reloads the captures itself. */
let expectedChange = false;

/** Whether the latest pcapViewer.prefs change came from _Protocol Preferences…_ (consumed). */
export function consumePrefsChange(): boolean {
  const expected = expectedChange;
  expectedChange = false;
  return expected;
}

const RESET_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("discard"),
  tooltip: "Reset (use Wireshark's value)",
};
const BROWSE_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("folder-opened"),
  tooltip: "Browse…",
};

export function registerPrefsCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    // `{protocol}` (the packet details' context menu) skips the protocol picker;
    // with `quiet: true` it returns the protocol's preferences and shows nothing (smoke test).
    vscode.commands.registerCommand(
      "pcapViewer.protocolPreferences",
      async (arg?: {
        protocol?: unknown;
        quiet?: unknown;
      }): Promise<{ prefs: ProtocolPref[] } | undefined> => {
        const protocol = typeof arg?.protocol === "string" ? arg.protocol : undefined;
        if (protocol && arg?.quiet === true) {
          return withBackend(provider, context, log, (backend) =>
            backend.request<{ prefs: ProtocolPref[] }>("protocol_prefs", { protocol }),
          );
        }
        try {
          await withBackend(provider, context, log, async (backend) => {
            const chosen = protocol ?? (await pickProtocol(backend));
            if (chosen) {
              await editPrefs(backend, chosen, provider.activeSession?.uri);
            }
          });
        } catch (err) {
          void vscode.window.showErrorMessage(
            `PCAP Lens: protocol preferences: ${describeError(err)}`,
          );
        }
        return undefined;
      },
    ),
  );
}

async function pickProtocol(backend: BackendClient): Promise<string | undefined> {
  const res = await backend.request<{ protocols: { protocol: string; count: number }[] }>(
    "protocol_prefs",
    {},
    { timeoutMs: 30_000 },
  );
  const pick = await vscode.window.showQuickPick(
    res.protocols.map((p) => ({
      label: p.protocol,
      description: `${p.count} preference${p.count === 1 ? "" : "s"}`,
    })),
    { title: "Protocol Preferences", placeHolder: "Protocol (e.g. tcp, tls, http)" },
  );
  return pick?.label;
}

type PrefItem = vscode.QuickPickItem & { pref: ProtocolPref };

/**
 * The protocol's preferences, each with the value in effect for the capture;
 * picking one asks for a new value, ↺ resets it. Stays open for more changes.
 */
async function editPrefs(
  backend: BackendClient,
  protocol: string,
  scope: vscode.Uri | undefined,
): Promise<void> {
  const res = await backend.request<{ prefs: ProtocolPref[] }>(
    "protocol_prefs",
    { protocol },
    { timeoutMs: 30_000 },
  );
  let active: string | undefined;
  for (;;) {
    const choice = await showPrefs(protocol, res.prefs, scope, active);
    if (!choice) {
      return;
    }
    active = choice.pref.name;
    if (choice.reset) {
      await writePref(choice.pref, undefined, scope);
      continue;
    }
    if (choice.pref.name === "tls.keylog_file") {
      // Its own setting (pcapViewer.tlsKeyLogFile) takes precedence over the preference.
      await vscode.commands.executeCommand("pcapViewer.setTlsKeyLogFile");
      return;
    }
    const current = effectivePref(choice.pref, overridesFor(scope)).value;
    const value = await askValue(choice.pref, current);
    if (value !== undefined) {
      await writePref(choice.pref, value, scope);
    }
  }
}

function overridesFor(scope: vscode.Uri | undefined): PrefOverrides {
  return getSetting<PrefOverrides>("prefs", {}, scope);
}

/** Show the list once: the preference picked (or reset), undefined when closed. */
function showPrefs(
  protocol: string,
  prefs: ProtocolPref[],
  scope: vscode.Uri | undefined,
  active: string | undefined,
): Promise<{ pref: ProtocolPref; reset: boolean } | undefined> {
  const overrides = overridesFor(scope);
  const items: PrefItem[] = prefs.map((pref) => {
    const { value, source } = effectivePref(pref, overrides);
    const where =
      source === "setting"
        ? " · changed here"
        : source === "wireshark"
          ? " · from your Wireshark preferences"
          : "";
    return {
      pref,
      label: prefLabel(pref.name),
      description: `${value === "" ? "(empty)" : value}${where}`,
      detail: pref.description ? `${pref.name}: ${pref.description}` : pref.name,
      buttons: source === "setting" ? [RESET_BUTTON] : [],
    };
  });
  const qp = vscode.window.createQuickPick<PrefItem>();
  qp.title = `Protocol Preferences: ${protocol}`;
  qp.placeholder = "Pick a preference to change it (the capture reloads); ↺ resets it";
  qp.matchOnDescription = true;
  qp.matchOnDetail = true;
  qp.items = items;
  const current = items.find((i) => i.pref.name === active);
  if (current) {
    qp.activeItems = [current];
  }
  return new Promise((resolve) => {
    let result: { pref: ProtocolPref; reset: boolean } | undefined;
    qp.onDidAccept(() => {
      const item = qp.selectedItems[0] ?? qp.activeItems[0];
      if (item) {
        result = { pref: item.pref, reset: false };
        qp.hide();
      }
    });
    qp.onDidTriggerItemButton((e) => {
      result = { pref: e.item.pref, reset: true };
      qp.hide();
    });
    qp.onDidHide(() => {
      qp.dispose();
      resolve(result);
    });
    qp.show();
  });
}

/** Ask for a new value: a pick for booleans and enums, else a checked input box. */
async function askValue(pref: ProtocolPref, current: string): Promise<string | undefined> {
  const title = `${prefLabel(pref.name)} (${pref.name})`;
  if (pref.type === "bool" || pref.type === "enum") {
    const options = pref.type === "bool" ? ["TRUE", "FALSE"] : (pref.choices ?? []);
    const pick = await vscode.window.showQuickPick(
      options.map((label) => ({
        label,
        description: [
          sameValue(pref, label, current) ? "current" : "",
          sameValue(pref, label, pref.default) ? "default" : "",
        ]
          .filter(Boolean)
          .join(", "),
      })),
      { title, placeHolder: pref.description },
    );
    return pick?.label;
  }
  const box = vscode.window.createInputBox();
  box.title = title;
  box.prompt = pref.description;
  box.value = current;
  box.placeholder = `Default: ${pref.default === "" ? "(empty)" : pref.default}`;
  if (pref.type === "file" || pref.type === "directory") {
    box.buttons = [BROWSE_BUTTON];
  }
  return new Promise((resolve) => {
    let result: string | undefined;
    box.onDidChangeValue((v) => {
      box.validationMessage = validatePrefValue(pref, v);
    });
    box.onDidAccept(() => {
      if (!validatePrefValue(pref, box.value)) {
        result = box.value;
        box.hide();
      }
    });
    box.onDidTriggerButton(async () => {
      const folder = pref.type === "directory";
      const uris = await vscode.window.showOpenDialog({
        canSelectFiles: !folder,
        canSelectFolders: folder,
        title,
      });
      if (uris?.[0]) {
        box.value = uris[0].fsPath;
      }
    });
    box.onDidHide(() => {
      box.dispose();
      resolve(result);
    });
    box.show();
  });
}

/** Store the change in pcapViewer.prefs (for the capture's folder); undefined resets. */
async function writePref(
  pref: ProtocolPref,
  input: string | undefined,
  scope: vscode.Uri | undefined,
): Promise<void> {
  const overrides = overridesFor(scope);
  const next = withPref(
    overrides,
    pref,
    input === undefined ? undefined : prefSettingValue(pref, input),
  );
  if (!samePrefs(next, overrides)) {
    expectedChange = true;
    await updateSetting("prefs", next, scope);
  }
}
