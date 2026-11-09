import * as vscode from "vscode";
import { getSetting, updateSetting } from "../config";
import type { PcapEditorProvider } from "../pcapEditor";
import { ColoringPanel } from "../panels/coloringPanel";
import {
  COLORIZE_FOREGROUND,
  COLORIZE_PALETTE,
  ColoringRule,
  prependColoringRule,
} from "../settingsModel";

/**
 * "PCAP: Colorize with Filter…": add a coloring rule at the top of
 * `pcapViewer.coloringRules` (so it wins) and make sure coloring is on.
 * Also reached from the detail tree's context menu with the field's filter.
 */
export async function colorizeWithFilter(
  provider: PcapEditorProvider,
  arg?: unknown,
): Promise<ColoringRule | undefined> {
  const session = provider.activeSession;
  // A filter (the tree's menu), or {filter, color, name}: color is a palette
  // entry's label or background, and both skip their questions.
  const given = arg && typeof arg === "object" ? (arg as Record<string, unknown>) : {};
  const filter = typeof arg === "string" ? arg : given.filter;
  let expr = typeof filter === "string" ? filter.trim() : "";
  if (!expr) {
    expr =
      (
        await vscode.window.showInputBox({
          title: "Colorize with Filter",
          prompt: "Display filter of the packets to color",
          value: session?.currentFilter ?? "",
          validateInput: async (text) =>
            !text.trim()
              ? "Enter a display filter"
              : text.includes("@")
                ? "Coloring rules cannot contain '@'"
                : await session?.validateFilter(text),
        })
      )?.trim() ?? "";
    if (!expr) {
      return undefined;
    }
  }
  const colors = COLORIZE_PALETTE.map((c) => ({
    label: c.label,
    description: c.background,
    background: c.background,
  }));
  let color: (typeof colors)[number] | undefined;
  if (typeof given.color === "string") {
    const wanted = given.color.toLowerCase();
    color = colors.find((c) => c.label.toLowerCase() === wanted || c.background === wanted);
    if (!color) {
      void vscode.window.showErrorMessage(
        `PCAP Lens: "${given.color}" isn't one of the colors (${colors.map((c) => c.label).join(", ")}).`,
      );
      return undefined;
    }
  } else {
    color = await vscode.window.showQuickPick(colors, {
      title: `Colorize: ${expr}`,
      placeHolder: "Row color",
    });
  }
  if (!color) {
    return undefined;
  }
  const name =
    typeof given.name === "string"
      ? given.name
      : await vscode.window.showInputBox({
          title: "Colorize: rule name",
          value: expr,
          prompt: "Shown in the coloring rules setting",
        });
  if (name === undefined) {
    return undefined;
  }
  const rule: ColoringRule = {
    name: name.trim() || expr,
    filter: expr,
    foreground: COLORIZE_FOREGROUND,
    background: color.background,
  };
  const scope = session?.uri;
  await updateSetting(
    "coloringRules",
    prependColoringRule(getSetting<unknown>("coloringRules", [], scope), rule),
    scope,
  );
  if (!getSetting<boolean>("colorize", true, scope)) {
    await updateSetting("colorize", true, scope);
  }
  return rule;
}

export function registerColoringCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.colorizeWithFilter", (arg?: unknown) =>
      colorizeWithFilter(provider, arg),
    ),
    vscode.commands.registerCommand("pcapViewer.toggleColoring", async () => {
      const scope = provider.activeSession?.uri;
      const on = !getSetting<boolean>("colorize", true, scope);
      await updateSetting("colorize", on, scope);
      vscode.window.setStatusBarMessage(`Packet coloring ${on ? "on" : "off"}`, 3000);
    }),
    vscode.commands.registerCommand("pcapViewer.resetColorization", () => {
      const session = provider.activeSession;
      if (!session?.resetColorization()) {
        vscode.window.setStatusBarMessage("No conversation is colorized", 3000);
      }
    }),
    vscode.commands.registerCommand("pcapViewer.manageColoringRules", () =>
      ColoringPanel.show(context, provider),
    ),
  );
}
