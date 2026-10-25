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

/**
 * Why a model can't serve PCAP Lens: VS Code keeps some models for its own
 * chat ("Model … is only available to VS Code core"), and some entries
 * answer an extension's request with nothing (Copilot CLI's "Auto"). Both
 * are listed by `lm.selectChatModels` all the same.
 */
export type Unusable = "core-only" | "empty";

/** The reason `error` (or an empty `answer`, when there was no error) says the model can't be used. */
export function unusableReason(error: unknown, answer?: string): Unusable | undefined {
  if (error !== undefined) {
    const message = error instanceof Error ? error.message : String(error);
    return /only available to VS Code core|not available to extensions/i.test(message)
      ? "core-only"
      : undefined;
  }
  return answer !== undefined && !answer.trim() ? "empty" : undefined;
}

/** A request the model can't serve (see `Unusable`); ai.ts turns it into `unusableMessage`. */
export class UnusableModelError extends Error {
  constructor(
    readonly label: string,
    readonly modelId: string,
    readonly reason: Unusable,
  ) {
    super(`${label}: ${reason === "core-only" ? "only VS Code may use it" : "empty answer"}`);
    this.name = "UnusableModelError";
  }
}

/** "GPT-x (GitHub Copilot) is reserved for VS Code's own chat and doesn't answer extensions". */
export function unusableWhy(label: string, reason: Unusable): string {
  return reason === "core-only"
    ? `${label} is reserved for VS Code's own chat and doesn't answer extensions`
    : `${label} sent an empty answer`;
}

/**
 * What to tell the user. Automatic: the next request skips this model and
 * takes another Copilot one; a chosen model: pick another (never a silent
 * switch, see the module comment).
 */
export function unusableMessage(label: string, reason: Unusable, automatic: boolean): string {
  const why = unusableWhy(label, reason);
  return automatic
    ? `${why}. Try again: PCAP Lens will use another GitHub Copilot model, or pick one with PCAP: Choose Language Model….`
    : `${why}. Pick another model with PCAP: Choose Language Model….`;
}

/**
 * The automatic choice: Copilot's first model that hasn't failed this way
 * (`skipped` ids), else the first (the user may have fixed what was wrong).
 */
export function automaticModel<T extends Pick<ModelInfo, "id">>(
  models: readonly T[],
  skipped: ReadonlySet<string>,
): T | undefined {
  return models.find((m) => !skipped.has(m.id)) ?? models[0];
}
