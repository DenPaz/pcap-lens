/**
 * Which language model the AI features use (`pcapViewer.ai.model`). Empty:
 * automatic, GitHub Copilot's first model, as before the setting existed. A
 * model id: that model only, whichever extension provides it (another vendor,
 * a local model), and nothing falls back to a different model when it is
 * missing: someone who picked a local model to keep captures on the machine
 * must not have them sent to a cloud model instead. No `vscode` import.
 */

/** What PCAP Lens needs of a `vscode.LanguageModelChat`. */
export interface ModelInfo {
  id: string;
  name: string;
  vendor: string;
  family: string;
  maxInputTokens: number;
}

/** The selector for `vscode.lm.selectChatModels` (application-scoped setting). */
export function modelSelector(setting: string): { vendor?: string; id?: string } {
  const id = setting.trim();
  return id ? { id } : { vendor: "copilot" };
}

const VENDORS: Record<string, string> = { copilot: "GitHub Copilot" };

/** A vendor as people know it ("copilot" → "GitHub Copilot"). */
export function vendorLabel(vendor: string): string {
  return VENDORS[vendor] ?? vendor;
}

/** "GPT-4o (GitHub Copilot)". */
export function modelLabel(model: Pick<ModelInfo, "name" | "vendor">): string {
  return `${model.name} (${vendorLabel(model.vendor)})`;
}

export interface ModelItem {
  /** The setting's value when picked ("" = automatic); undefined for a separator. */
  id?: string;
  label: string;
  description?: string;
  detail?: string;
  picked?: boolean;
  separator?: boolean;
}

/**
 * The picker's rows: Automatic first, then every model by vendor (Copilot's
 * first), the one in use marked. A chosen model that is gone stays listed, so
 * the picker says what the setting holds.
 */
export function modelItems(models: readonly ModelInfo[], setting: string): ModelItem[] {
  const current = setting.trim();
  const items: ModelItem[] = [
    {
      id: "",
      label: "Automatic",
      description: current ? undefined : "in use",
      detail: "GitHub Copilot's model, when Copilot is installed and signed in",
      picked: !current,
    },
  ];
  const vendors = [...new Set(models.map((m) => m.vendor))].sort((a, b) =>
    a === "copilot" ? -1 : b === "copilot" ? 1 : vendorLabel(a).localeCompare(vendorLabel(b)),
  );
  for (const vendor of vendors) {
    items.push({ label: vendorLabel(vendor), separator: true });
    for (const m of models
      .filter((x) => x.vendor === vendor)
      .sort((a, b) => a.name.localeCompare(b.name))) {
      items.push({
        id: m.id,
        label: m.name,
        description: [m.family !== m.name ? m.family : "", m.id === current ? "in use" : ""]
          .filter(Boolean)
          .join(" · "),
        detail: `${m.maxInputTokens.toLocaleString("en-US")} input tokens · id ${m.id}`,
        picked: m.id === current,
      });
    }
  }
  if (current && !models.some((m) => m.id === current)) {
    items.push(
      { label: "Not available now", separator: true },
      {
        id: current,
        label: current,
        description: "in use",
        detail: "The model chosen before: its extension isn't installed, enabled or signed in",
        picked: true,
      },
    );
  }
  return items;
}

/** Why AI help can't answer: refused access, the chosen model is missing, or no Copilot. */
export function unavailableMessage(setting: string, blocked: boolean): string {
  if (blocked) {
    return "AI help was not allowed to use the language model.";
  }
  const id = setting.trim();
  return id
    ? `The language model chosen in pcapViewer.ai.model ("${id}") isn't available. Pick another with PCAP: Choose Language Model…`
    : "No language model is available. Install and sign in to GitHub Copilot, or pick another model with PCAP: Choose Language Model…, to use AI help.";
}
