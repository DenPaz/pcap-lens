import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import {
  type ImportKind,
  type ProfileContents,
  type ProfileEntry,
  importChoices,
  importSettings,
  profileItems,
} from "../wiresharkProfile";
import { withBackend } from "./withBackend";

type Ctx = {
  provider: PcapEditorProvider;
  context: vscode.ExtensionContext;
  log: vscode.LogOutputChannel;
};

async function listProfiles(c: Ctx): Promise<ProfileEntry[]> {
  const result = await withBackend(c.provider, c.context, c.log, (client) =>
    client.request<{ profiles: ProfileEntry[] }>("wireshark_profiles", {}, { timeoutMs: 60_000 }),
  );
  return result.profiles;
}

async function pickProfile(
  profiles: readonly ProfileEntry[],
  current: string,
  title: string,
  placeHolder: string,
): Promise<string | undefined> {
  const chosen = await vscode.window.showQuickPick(profileItems(profiles, current), {
    title,
    placeHolder,
    matchOnDescription: true,
    matchOnDetail: true,
  });
  return chosen?.name;
}

/**
 * _PCAP: Use Wireshark Profile…_: the configuration profile tshark runs with
 * (`-C`: its preferences, Decode As, display filter macros, disabled
 * protocols…), written to `pcapViewer.wiresharkProfile` for the active
 * capture's folder; captures it changes reload. `{profile}` skips the picker
 * ("" = Default). Returns the profile chosen.
 */
export async function useProfile(c: Ctx, args?: { profile?: string }): Promise<string | undefined> {
  const scope = c.provider.activeSession?.uri;
  const current = readSettings(scope).wiresharkProfile;
  let name = args?.profile;
  if (name === undefined) {
    let profiles: ProfileEntry[];
    try {
      profiles = await listProfiles(c);
    } catch (err) {
      void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
      return undefined;
    }
    name = await pickProfile(
      profiles,
      current,
      "Use Wireshark Profile",
      "tshark uses the profile's preferences, Decode As rules and filter macros",
    );
    if (name === undefined) {
      return undefined;
    }
  }
  await updateSetting("wiresharkProfile", name, scope);
  c.log.info(`Wireshark profile: ${name || "Default"}`);
  return name;
}

/**
 * _PCAP: Import from Wireshark Profile…_: the settings PCAP Lens keeps itself
 * (coloring rules, filter buttons, saved display filters, columns) taken from
 * a profile, chosen per kind. `{profile, kinds}` skip the questions. Returns
 * what was imported (kind → entries).
 */
export async function importProfile(
  c: Ctx,
  args?: { profile?: string; kinds?: ImportKind[] },
): Promise<Partial<Record<ImportKind, number>> | undefined> {
  const scope = c.provider.activeSession?.uri;
  let contents: ProfileContents;
  try {
    let name = args?.profile;
    if (name === undefined) {
      name = await pickProfile(
        await listProfiles(c),
        "\0", // (none is checked: importing isn't using)
        "Import from Wireshark Profile",
        "Choose the profile to import coloring rules, filter buttons, saved filters and columns from",
      );
      if (name === undefined) {
        return undefined;
      }
    }
    const profile = name;
    contents = await withBackend(c.provider, c.context, c.log, (client) =>
      client.request<ProfileContents>(
        "read_wireshark_profile",
        { name: profile },
        { timeoutMs: 60_000 },
      ),
    );
  } catch (err) {
    c.log.error(
      `importing from Wireshark profile ${args?.profile ?? "(picked)"}: ${describeError(err)}`,
    );
    if (args?.kinds) {
      throw err; // (a caller that chose everything gets the reason, not a notification)
    }
    void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    return undefined;
  }
  const choices = importChoices(contents);
  if (!choices.length) {
    c.log.warn(`Wireshark profile ${contents.name} (${contents.path}): nothing to import`);
    void vscode.window.showInformationMessage(
      `PCAP Lens: the ${contents.name} profile has no coloring rules, filter buttons, saved filters or columns to import.`,
    );
    return {};
  }
  let kinds = args?.kinds;
  if (!kinds) {
    const picked = await vscode.window.showQuickPick(
      choices.map((ch) => ({
        label: ch.label,
        detail: ch.detail,
        picked: true,
        importKind: ch.kind,
      })),
      {
        title: `Import from Wireshark Profile: ${contents.name}`,
        placeHolder: "What to import",
        canPickMany: true,
      },
    );
    if (!picked?.length) {
      return undefined;
    }
    kinds = picked.map((p) => p.importKind);
  }
  const settings = readSettings(scope);
  const imported: Partial<Record<ImportKind, number>> = {};
  for (const kind of kinds.filter((k) => choices.some((ch) => ch.kind === k))) {
    const { writes, added } = importSettings(kind, contents, settings);
    for (const w of writes) {
      await updateSetting(w.key, w.value, scope);
    }
    imported[kind] = added;
  }
  const summary = choices
    .filter((ch) => ch.kind in imported)
    .map((ch) => ch.label)
    .join(", ");
  c.log.info(`imported from Wireshark profile ${contents.name} (${contents.path}): ${summary}`);
  if (!args?.kinds) {
    // Preferences, Decode As and macros aren't settings: tshark reads them when it uses the profile.
    const rest = contents.preferences + contents.decodeAs + contents.macros.length;
    const use = "Use This Profile";
    const choice = await vscode.window.showInformationMessage(
      `PCAP Lens: imported ${summary} from the ${contents.name} profile.` +
        (rest && contents.name !== "Default"
          ? " Its preferences, Decode As rules and filter macros apply when tshark uses the profile."
          : ""),
      ...(rest && contents.name !== "Default" ? [use] : []),
    );
    if (choice === use) {
      await useProfile(c, { profile: contents.name });
    }
  }
  return imported;
}

export function registerProfileCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  const c = { provider, context, log };
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.wiresharkProfile", (args?: { profile?: string }) =>
      useProfile(c, args),
    ),
    vscode.commands.registerCommand(
      "pcapViewer.importWiresharkProfile",
      (args?: { profile?: string; kinds?: ImportKind[] }) => importProfile(c, args),
    ),
  );
}
