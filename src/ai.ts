/**
 * Optional AI help through VS Code's Language Model API (`vscode.lm`, stable
 * since 1.90). Copilot's inline completions can't reach the webview filter
 * bar, so the extension host asks a chat model directly.
 *
 * - Display filters (aiFilter.ts): only the request, the current filter,
 *   protocol names and field names/descriptions are sent, never packet data.
 * - Capture filters (aiCaptureFilter.ts) and Lua dissectors (aiDissector.ts):
 *   only the description, the current capture filter and interface names, or
 *   the dissector template; dumpcap and tshark check what comes back.
 * - Explaining packets (aiExplain.ts, `@pcap /explain`): sends the packets'
 *   rows and dissection trees, so callers first get the user's consent
 *   (`pcapViewer.ai.allowPacketData`, see commands/ai.ts). Raw bytes only
 *   with `pcapViewer.ai.allowPacketBytes`.
 * - Capture summary (aiSummary.ts, `@pcap /summary`), anomaly explanations
 *   (aiAnomaly.ts, `@pcap /anomaly`) and @pcap's tools (aiTools.ts): send
 *   statistics computed by tshark, never packet contents; callers first get
 *   the consent of `pcapViewer.ai.allowCaptureStatistics` (aiConsent.ts).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import type { BackendClient } from "./backendClient";
import { SECTION } from "./config";
import {
  EXPLAIN_LIMITS,
  ExplainPacket,
  TreeNode,
  buildExplainPrompt,
  extractFilters,
} from "./aiExplain";
import {
  AnomalyTarget,
  CallSummary,
  ExpertRow,
  TcpPoint,
  buildCallPrompt,
  buildExpertPrompt,
  buildTcpPrompt,
  expertRowsFromTable,
  framesFilter,
  notableExpertRows,
  ANOMALY_LIMITS,
} from "./aiAnomaly";
import { Requester, StatsTable, buildSummaryPrompt, gatherSummary } from "./aiSummary";
import { CaptureDiff, buildComparePrompt } from "./aiCompare";
import { ToolConsent, TOOL_LIMITS, buildToolPrompt, runTool, runToolLoop } from "./aiTools";
import { toolsRuntime } from "./lmTools";
import {
  ModelInfo,
  UnusableModelError,
  automaticModel,
  modelLabel,
  modelSelector,
  unavailableMessage,
  unusableMessage,
  unusableReason,
} from "./aiModel";
import {
  AddressMasker,
  maskedLoopModel,
  namesInRows,
  namesInTree,
  withStandInNote,
} from "./aiPrivacy";
import type { QuickDetail } from "./settingsModel";
import {
  ChatTurn,
  FieldInfo,
  FilterSuggestion,
  Rejected,
  extractKeywords,
  suggestFilters,
} from "./aiFilter";
import { suggestCaptureFilters } from "./aiCaptureFilter";
import { DissectorRequest, DissectorResult, generateDissector } from "./aiDissector";
import {
  TRIAGE_RETRY,
  TriageCheck,
  TriageReport,
  buildTriagePrompt,
  gatherTriage,
  parseTriage,
} from "./aiTriage";

/** A triage: the findings (filters validated, packets from the data), and the checks they came from. */
export interface TriageOutcome extends ExplainOutcome {
  report?: TriageReport;
  checks?: TriageCheck[];
  /** The model that wrote it ("GPT-4o (GitHub Copilot)"). */
  model?: string;
}

export interface DissectorOutcome extends DissectorResult {
  /** Short user-facing note when there is no script (or it couldn't be loaded). */
  message?: string;
  unavailable?: boolean;
  /** Why tshark couldn't load the script to check it (Lua off as root). */
  unchecked?: string;
}

export interface SuggestOutcome {
  suggestions: FilterSuggestion[];
  rejected: Rejected[];
  /** Short user-facing note when there are no suggestions (or they were cut short). */
  message?: string;
  /** AI help can't be used right now (off, no model, no permission): hide the action. */
  unavailable?: boolean;
}

const JUSTIFICATION =
  "PCAP Lens turns your description into a Wireshark display filter. Only your request, the current filter and protocol/field names are sent.";
const CAPTURE_FILTER_JUSTIFICATION =
  "PCAP Lens turns your description into a capture filter. Only your request, the current capture filter and the interface names are sent.";
const DISSECTOR_JUSTIFICATION =
  "PCAP Lens writes a Lua dissector from your description. Only your description and its dissector template are sent.";
const TRIAGE_JUSTIFICATION =
  "PCAP Lens triages the open capture from check counts and statistics computed by tshark (no packet contents).";
const EXPLAIN_JUSTIFICATION =
  "PCAP Lens explains the packets you picked. Their packet-list rows and dissection trees are sent.";
const COMPARE_JUSTIFICATION =
  "PCAP Lens compares two captures' statistics (totals, check counts, flows, endpoints, expert information) to explain what changed.";
const SUMMARY_JUSTIFICATION =
  "PCAP Lens summarizes the open capture from statistics computed by tshark (no packet contents).";
const ANOMALY_JUSTIFICATION =
  "PCAP Lens explains expert information or a TCP stream from statistics computed by tshark (no packet contents).";
const TOOLS_JUSTIFICATION =
  "PCAP Lens answers questions about the open capture with read-only tools (counts and statistics).";

/** What to explain (the caller has the user's consent to send packet data). */
export interface ExplainRequest {
  frames: number[];
  question: string;
  currentFilter: string;
  /** Column title by field, for the packet-list row. */
  titleOf: Record<string, string>;
  customFields: string[];
  includeBytes: boolean;
  /** Late packets use the quick (approximate) detail, like the viewer (pcapViewer.quickDetail). */
  quickDetail: QuickDetail;
}

/** Where the answer goes while it streams (chat response, or an editor). */
export interface ExplainSink {
  progress(message: string): void;
  markdown(text: string): void;
}

export interface ExplainOutcome {
  /** The packets that were explained (Go to packet buttons). */
  frames: number[];
  /** Display filters from the answer that tshark accepts. */
  filters: string[];
  /** Short user-facing note when nothing (or not everything) was explained. */
  message?: string;
  /** AI help can't be used right now (off, no model, no permission). */
  unavailable?: boolean;
  /** Tools that weren't allowed to answer (the settings that would allow them). */
  refused?: ("statistics" | "packetData")[];
}

/** An anomaly to explain: expert rows (given, or the capture's errors and warnings) or a TCP stream. */
export interface AnomalyRequest {
  target: AnomalyTarget;
  /** The expert rows the panel sent (else the capture's notable ones). */
  rows?: ExpertRow[];
  /** The call the VoIP panel sent (target "call"). */
  call?: CallSummary;
  question: string;
  currentFilter: string;
}
const FIELDS_PER_KEYWORD = 12;

/**
 * `run` (a request to `model` and reading its answer), with VS Code's refusal
 * of a model kept for its own chat, or an empty answer, as UnusableModelError.
 */
async function answerFrom(
  model: vscode.LanguageModelChat,
  token: vscode.CancellationToken,
  run: () => Promise<string>,
): Promise<string> {
  let answer: string;
  try {
    answer = await run();
  } catch (err) {
    const reason = unusableReason(err);
    throw reason ? new UnusableModelError(modelLabel(model), model.id, reason) : err;
  }
  if (!token.isCancellationRequested && unusableReason(undefined, answer)) {
    throw new UnusableModelError(modelLabel(model), model.id, "empty");
  }
  return answer;
}

function lmApi(): typeof vscode.lm | undefined {
  // Guard against hosts that ship without the API (it is stable in 1.90, our minimum).
  return typeof vscode.lm?.selectChatModels === "function" ? vscode.lm : undefined;
}

/**
 * One filter-help request: the turns go out with stand-ins for addresses
 * (the note on the first turn) and the answer comes back with them restored.
 */
function askFor(
  model: vscode.LanguageModelChat,
  masker: AddressMasker,
  justification: string,
  token: vscode.CancellationToken,
): (turns: ChatTurn[]) => Promise<string> {
  return async (turns) => {
    const messages = turns.map((t, i) => {
      const content = masker.mask(t.content);
      return t.role === "user"
        ? vscode.LanguageModelChatMessage.User(i === 0 ? withStandInNote(masker, content) : content)
        : vscode.LanguageModelChatMessage.Assistant(content);
    });
    const text = await answerFrom(model, token, async () => {
      const response = await model.sendRequest(messages, { justification }, token);
      let all = "";
      for await (const part of response.text) {
        all += part;
      }
      return all;
    });
    return masker.restore(text);
  };
}

/** `backend.request` as the pure modules' `Requester`. */
const request =
  (backend: BackendClient): Requester =>
  (method, params, options) =>
    backend.request(method, params, options);

/** `promise`, or a CancellationError as soon as `token` is cancelled. */
function untilCancelled<T>(promise: Promise<T>, token: vscode.CancellationToken): Promise<T> {
  if (token.isCancellationRequested) {
    return Promise.reject(new vscode.CancellationError());
  }
  return new Promise<T>((resolve, reject) => {
    const sub = token.onCancellationRequested(() => {
      sub.dispose();
      reject(new vscode.CancellationError());
    });
    promise.then(
      (v) => {
        sub.dispose();
        resolve(v);
      },
      (e: unknown) => {
        sub.dispose();
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

/** What a tool call shows while it runs ("Counting dns…"). */
export function describeToolCall(name: string, input: unknown): string {
  const args = (input && typeof input === "object" ? input : {}) as Record<string, unknown>;
  const filter = typeof args.filter === "string" && args.filter ? ` ${args.filter}` : "";
  switch (name) {
    case "pcap_count":
      return `Counting${filter || " all packets"}…`;
    case "pcap_stats":
      return `Reading ${String(args.kind ?? "")} statistics${filter ? ` for${filter}` : ""}…`;
    case "pcap_capture_info":
      return "Reading the capture's properties…";
    case "pcap_field_search":
      return `Looking up fields ${String(args.prefix ?? "")}…`;
    case "pcap_list_packets":
      return `Listing packets${filter}…`;
    default:
      return `Running ${name}…`;
  }
}

export function aiEnabled(): boolean {
  return vscode.workspace.getConfiguration(SECTION).get<boolean>("ai.enabled", true);
}

/** `pcapViewer.ai.model`: a model id, or "" for automatic (application-scoped). */
export function modelSetting(): string {
  return vscode.workspace.getConfiguration(SECTION).get<string>("ai.model", "") ?? "";
}

/** `pcapViewer.ai.pseudonymizeAddresses` (application-scoped, on by default). */
export function pseudonymizing(): boolean {
  return vscode.workspace.getConfiguration(SECTION).get<boolean>("ai.pseudonymizeAddresses", true);
}

/** Every chat model VS Code offers now (for PCAP: Choose Language Model…). */
export async function listModels(): Promise<ModelInfo[]> {
  const lm = lmApi();
  if (!lm) {
    return [];
  }
  try {
    return (await lm.selectChatModels()).map((m) => ({
      id: m.id,
      name: m.name,
      vendor: m.vendor,
      family: m.family,
      maxInputTokens: m.maxInputTokens,
    }));
  } catch {
    return [];
  }
}

export class FilterAssistant implements vscode.Disposable {
  /** Set when the user denied (or policy blocked) access; cleared when models or settings change. */
  private blocked = false;
  /** Copilot models that failed as UnusableModelError: the automatic choice skips them. */
  private readonly skipped = new Set<string>();
  private readonly availability = new vscode.EventEmitter<void>();
  /** Fires when AI help may have become (un)available; re-check with isAvailable(). */
  readonly onDidChangeAvailability = this.availability.event;
  private readonly disposables: vscode.Disposable[] = [this.availability];
  /** Stand-ins per capture: a token means the same address in every request about it. */
  private readonly maskers = new WeakMap<BackendClient, AddressMasker>();
  /** Protocol names per backend (one protocol-hierarchy pass per capture). */
  private readonly protocols = new WeakMap<BackendClient, Promise<string[]>>();

  constructor(private readonly log: vscode.LogOutputChannel) {
    const lm = lmApi();
    if (lm?.onDidChangeChatModels) {
      this.disposables.push(lm.onDidChangeChatModels(() => this.changed()));
    }
    this.disposables.push(
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (
          e.affectsConfiguration(`${SECTION}.ai.enabled`) ||
          e.affectsConfiguration(`${SECTION}.ai.model`)
        ) {
          this.changed();
        }
      }),
    );
  }

  private changed(): void {
    this.blocked = false;
    this.availability.fire();
  }

  /** The capture's stand-ins (a new set when pcapViewer.ai.pseudonymizeAddresses changed). */
  maskerFor(backend: BackendClient): AddressMasker {
    const on = pseudonymizing();
    let masker = this.maskers.get(backend);
    if (!masker || masker.enabled !== on) {
      masker = new AddressMasker(on);
      this.maskers.set(backend, masker);
    }
    return masker;
  }

  async isAvailable(): Promise<boolean> {
    return !!(await this.model());
  }

  private async model(): Promise<vscode.LanguageModelChat | undefined> {
    const lm = lmApi();
    if (!aiEnabled() || this.blocked || !lm) {
      return undefined;
    }
    try {
      // (The chosen model only: never another vendor's instead.)
      const setting = modelSetting();
      const models = await lm.selectChatModels(modelSelector(setting));
      return setting.trim() ? models[0] : automaticModel(models, this.skipped);
    } catch {
      return undefined;
    }
  }

  /** The model to suggest filters with, or why there is none. */
  private async suggestModel(): Promise<vscode.LanguageModelChat | SuggestOutcome> {
    if (!aiEnabled()) {
      return {
        suggestions: [],
        rejected: [],
        unavailable: true,
        message: "AI help is turned off (pcapViewer.ai.enabled).",
      };
    }
    return (
      (await this.model()) ?? {
        suggestions: [],
        rejected: [],
        unavailable: true,
        message: unavailableMessage(modelSetting(), this.blocked),
      }
    );
  }

  /** Suggest validated display filters for `request` on the capture served by `backend`. */
  async suggest(
    backend: BackendClient,
    request: string,
    currentFilter: string,
    token: vscode.CancellationToken,
  ): Promise<SuggestOutcome> {
    const model = await this.suggestModel();
    if ("suggestions" in model) {
      return model;
    }
    try {
      // The first protocol-hierarchy pass can take a while on a big capture: don't make a cancel wait for it.
      const [protocols, fields] = await untilCancelled(
        Promise.all([this.protocolNames(backend), this.candidateFields(backend, request)]),
        token,
      );
      const ask = askFor(model, this.maskerFor(backend), JUSTIFICATION, token);
      const validate = async (filter: string): Promise<string | undefined> => {
        try {
          const res = await backend.request<{ valid: boolean; error?: string }>("validate_filter", {
            expr: filter,
          });
          return res.valid ? undefined : (res.error ?? "invalid filter");
        } catch (err) {
          return `could not validate: ${(err as Error).message}`;
        }
      };
      const result = await suggestFilters(
        { ask, validate },
        { request, currentFilter, protocols, fields },
      );
      for (const r of result.rejected) {
        this.log.info(`AI filter suggestion rejected by tshark: ${r.filter} (${r.error})`);
      }
      return result.suggestions.length
        ? result
        : {
            ...result,
            message:
              "The language model didn't come up with a valid display filter. Try describing it differently.",
          };
    } catch (err) {
      return this.failure(err, token);
    }
  }

  /**
   * Suggest capture (BPF) filters for `request`, each compiled by dumpcap for
   * `interfaces[0]` (`validate_capture_filter`). Only the request, the
   * current capture filter and the interface names are sent.
   */
  async suggestCaptureFilters(
    backend: BackendClient,
    request: string,
    currentFilter: string,
    interfaces: readonly { name: string; loopback?: boolean }[],
    token: vscode.CancellationToken,
  ): Promise<SuggestOutcome> {
    const model = await this.suggestModel();
    if ("suggestions" in model) {
      return model;
    }
    try {
      const ask = askFor(model, this.maskerFor(backend), CAPTURE_FILTER_JUSTIFICATION, token);
      const validate = async (filter: string): Promise<string | undefined> => {
        try {
          const res = await backend.request<{
            valid: boolean;
            checked?: boolean;
            error?: string;
            message?: string;
          }>("validate_capture_filter", { filter, interface: interfaces[0]?.name ?? "" });
          // dumpcap couldn't check it (no permission): accepted, as the input box does.
          return res.valid || res.checked === false
            ? undefined
            : (res.error ?? res.message ?? "invalid capture filter");
        } catch (err) {
          return `could not validate: ${(err as Error).message}`;
        }
      };
      const result = await suggestCaptureFilters(
        { ask, validate },
        { request, currentFilter, interfaces },
      );
      for (const r of result.rejected) {
        this.log.info(`AI capture filter suggestion rejected by dumpcap: ${r.filter} (${r.error})`);
      }
      return result.suggestions.length
        ? result
        : {
            ...result,
            message:
              "The language model didn't come up with a valid capture filter. Try describing it differently.",
          };
    } catch (err) {
      return this.failure(err, token);
    }
  }

  /**
   * A Lua dissector for `req` from the model, screened and then loaded by
   * tshark (`check_dissectors`, from a temporary copy) until it loads or the
   * rounds run out. Only the description and the template are sent.
   */
  async generateDissector(
    backend: BackendClient,
    req: DissectorRequest,
    template: string,
    token: vscode.CancellationToken,
    progress?: (round: number, problems: readonly string[]) => void,
  ): Promise<DissectorOutcome> {
    const model = await this.suggestModel();
    if ("suggestions" in model) {
      return { ok: false, problems: [], rounds: 0, ...model };
    }
    let unchecked: string | undefined;
    const check = async (source: string): Promise<string[]> => {
      // tshark's AppArmor profile lets it read the temp folder.
      const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pcap-lens-lua-"));
      const file = path.join(dir, `${req.name}.lua`);
      try {
        await fs.promises.writeFile(file, source);
        const res = await backend.request<{
          errors: { message: string }[];
          warnings: string[];
        }>("check_dissectors", { lua: [file] }, { timeoutMs: 60_000 });
        unchecked = res.warnings.find((w) => /root/i.test(w));
        return res.errors.map((e) => e.message.split(file).join(`${req.name}.lua`));
      } finally {
        await fs.promises.rm(dir, { recursive: true, force: true });
      }
    };
    try {
      const ask = askFor(model, this.maskerFor(backend), DISSECTOR_JUSTIFICATION, token);
      const result = await generateDissector({ ask, check }, req, template, progress);
      for (const p of result.problems) {
        this.log.info(`AI Lua dissector (round ${result.rounds}): ${p}`);
      }
      return { ...result, unchecked };
    } catch (err) {
      const f = this.failure(err, token);
      return { ok: false, problems: [], rounds: 0, message: f.message, unavailable: f.unavailable };
    }
  }

  private failure(err: unknown, token: vscode.CancellationToken): SuggestOutcome {
    if (token.isCancellationRequested || err instanceof vscode.CancellationError) {
      return { suggestions: [], rejected: [], message: "Cancelled." };
    }
    if (err instanceof UnusableModelError) {
      const automatic = !modelSetting().trim();
      if (automatic) {
        this.skipped.add(err.modelId);
      }
      this.log.warn(`AI: ${err.message}${automatic ? " (skipped from now on)" : ""}`);
      return {
        suggestions: [],
        rejected: [],
        message: unusableMessage(err.label, err.reason, automatic),
      };
    }
    if (err instanceof vscode.LanguageModelError) {
      this.log.warn(`AI filter help: ${err.code}: ${err.message}`);
      if (
        err.code === vscode.LanguageModelError.NoPermissions.name ||
        err.code === vscode.LanguageModelError.Blocked.name
      ) {
        this.blocked = true;
        this.availability.fire();
        return {
          suggestions: [],
          rejected: [],
          unavailable: true,
          message: "AI help was not allowed to use the language model.",
        };
      }
      if (err.code === vscode.LanguageModelError.NotFound.name) {
        this.availability.fire();
        return {
          suggestions: [],
          rejected: [],
          unavailable: true,
          message: "The language model is no longer available.",
        };
      }
    } else {
      this.log.warn(`AI request failed: ${(err as Error)?.message ?? err}`);
    }
    return {
      suggestions: [],
      rejected: [],
      message: `AI request failed: ${(err as Error)?.message ?? err}`,
    };
  }

  /**
   * Explain packets: their rows (list_packets) and dissection trees
   * (packet_detail) go into the prompt (aiExplain.ts caps them and leaves
   * raw bytes out unless `includeBytes`), the answer streams into `sink`, and
   * the ```filter blocks it contains are checked with tshark.
   */
  async explain(
    backend: BackendClient,
    req: ExplainRequest,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const none = { frames: [], filters: [] };
    if (!aiEnabled()) {
      return {
        ...none,
        unavailable: true,
        message: "AI help is turned off (pcapViewer.ai.enabled).",
      };
    }
    const model = await this.model();
    if (!model) {
      return {
        ...none,
        unavailable: true,
        message: unavailableMessage(modelSetting(), this.blocked),
      };
    }
    const included = req.frames.slice(0, EXPLAIN_LIMITS.maxPackets);
    try {
      sink.progress(`Reading packet${included.length === 1 ? "" : "s"} ${included.join(", ")}…`);
      type Rows = {
        rows: { number: number; cells: string[]; addresses?: string[] }[];
        columns: string[];
      };
      type Detail = {
        tree: TreeNode[];
        sources: { name: string; hex: string }[];
        approximate?: boolean;
        window?: [number, number];
      };
      const q = req.quickDetail;
      const detailParams = (number: number) =>
        q.after > 0 && number > q.after && number > q.window
          ? { number, mode: "quick", window: q.window }
          : { number };
      const [rows, details] = await untilCancelled(
        Promise.all([
          backend.request<Rows>(
            "list_packets",
            { frames: included, inView: false, columns: req.customFields, timeFormat: "relative" },
            { timeoutMs: 0 },
          ),
          Promise.all(
            included.map((number) =>
              backend
                .request<Detail>("packet_detail", detailParams(number), { timeoutMs: 0 })
                // No editcap: a quick request answers {unavailable}; use the exact detail then.
                .then((d) =>
                  d.tree
                    ? d
                    : backend.request<Detail>("packet_detail", { number }, { timeoutMs: 0 }),
                )
                .catch(() => undefined),
            ),
          ),
        ]),
        token,
      );
      const masker = this.maskerFor(backend);
      // (Bytes hold the addresses too, and they can't be replaced there.)
      const includeBytes = req.includeBytes && !masker.enabled;
      masker.learnNames(namesInRows(rows.rows));
      const packets: ExplainPacket[] = [];
      included.forEach((number, i) => {
        const detail = details[i];
        const row = rows.rows.find((r) => r.number === number);
        if (detail?.tree && row) {
          packets.push({
            number,
            cells: row.cells,
            tree: detail.tree,
            hex: includeBytes ? detail.sources[0]?.hex : undefined,
            approximateFrom: detail.approximate && detail.window ? detail.window[0] : undefined,
          });
        }
      });
      if (!packets.length) {
        return { ...none, message: `The capture has no packet ${req.frames.join(", ")}.` };
      }
      for (const p of packets) {
        masker.learnNames(namesInTree(p.tree));
      }
      const prompt = buildExplainPrompt({
        question: req.question,
        currentFilter: req.currentFilter,
        titles: rows.columns.map((f) => req.titleOf[f] ?? f),
        packets,
        omitted: req.frames.length - packets.length,
        includeBytes,
      });
      const answer = await this.streamAnswer(
        model,
        prompt,
        EXPLAIN_JUSTIFICATION,
        sink,
        token,
        masker,
      );
      const filters = await this.validFilters(backend, extractFilters(answer), "explain");
      const skipped = req.frames.length - packets.length;
      const notes = [
        skipped
          ? `${skipped} of the ${req.frames.length} packets were not included (at most ${EXPLAIN_LIMITS.maxPackets} at a time).`
          : "",
        req.includeBytes && !includeBytes
          ? "Raw bytes were not sent: the addresses in them can't be replaced by stand-ins (pcapViewer.ai.pseudonymizeAddresses)."
          : "",
      ].filter(Boolean);
      return {
        frames: packets.map((p) => p.number),
        filters,
        message: notes.length ? notes.join(" ") : undefined,
      };
    } catch (err) {
      const failed = this.failure(err, token);
      return { ...none, message: failed.message, unavailable: failed.unavailable };
    }
  }

  /** The model, or the outcome that says why AI help can't answer now. */
  private async readyModel(): Promise<vscode.LanguageModelChat | ExplainOutcome> {
    const none = { frames: [], filters: [] };
    if (!aiEnabled()) {
      return {
        ...none,
        unavailable: true,
        message: "AI help is turned off (pcapViewer.ai.enabled).",
      };
    }
    const model = await this.model();
    return (
      model ?? {
        ...none,
        unavailable: true,
        message: unavailableMessage(modelSetting(), this.blocked),
      }
    );
  }

  /**
   * Send one prompt (addresses replaced by `masker`'s stand-ins) and stream
   * the answer, real values restored, into `sink`; returns the whole answer.
   */
  private async streamAnswer(
    model: vscode.LanguageModelChat,
    prompt: string,
    justification: string,
    sink: ExplainSink,
    token: vscode.CancellationToken,
    masker: AddressMasker,
  ): Promise<string> {
    sink.progress(`Asking ${modelLabel(model)}…`);
    return answerFrom(model, token, async () => {
      const response = await model.sendRequest(
        [vscode.LanguageModelChatMessage.User(withStandInNote(masker, masker.mask(prompt)))],
        { justification },
        token,
      );
      const restorer = masker.restorer();
      let answer = "";
      const emit = (text: string) => {
        if (text) {
          answer += text;
          sink.markdown(text);
        }
      };
      for await (const part of response.text) {
        emit(restorer.push(part));
      }
      emit(restorer.end());
      return answer;
    });
  }

  /** The filters tshark accepts (the others are logged). */
  private async validFilters(
    backend: BackendClient,
    filters: string[],
    what: string,
  ): Promise<string[]> {
    const out: string[] = [];
    for (const filter of filters) {
      const res = await backend
        .request<{ valid: boolean }>("validate_filter", { expr: filter })
        .catch(() => ({ valid: false }));
      if (res.valid) {
        out.push(filter);
      } else {
        this.log.info(`AI ${what}: filter rejected by tshark: ${filter}`);
      }
    }
    return out;
  }

  /** A failure as an outcome (cancelled, not allowed, model gone, error). */
  private failed(err: unknown, token: vscode.CancellationToken): ExplainOutcome {
    const f = this.failure(err, token);
    return { frames: [], filters: [], message: f.message, unavailable: f.unavailable };
  }

  /**
   * Summarize the capture from its statistics (aiSummary.ts): properties,
   * protocol hierarchy, top conversations and endpoints, expert information
   * and traffic over time. The caller has the statistics consent.
   */
  async summarize(
    backend: BackendClient,
    req: { question: string; currentFilter: string },
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const model = await this.readyModel();
    if (!("sendRequest" in model)) {
      return model;
    }
    try {
      sink.progress("Computing statistics with tshark…");
      const prompt = buildSummaryPrompt(
        await untilCancelled(
          gatherSummary(request(backend), req, (kind, message) =>
            this.log.info(`AI summary: ${kind} statistics failed: ${message}`),
          ),
          token,
        ),
      );
      const answer = await this.streamAnswer(
        model,
        prompt,
        SUMMARY_JUSTIFICATION,
        sink,
        token,
        this.maskerFor(backend),
      );
      return {
        frames: [],
        filters: await this.validFilters(backend, extractFilters(answer), "summary"),
      };
    } catch (err) {
      return this.failed(err, token);
    }
  }

  /**
   * Explain what changed between two captures (aiCompare.ts) from their
   * profiles (`capture_profile`), which the backend diffs (`compare_profiles`).
   * `backend` is the capture open in the viewer: its stand-ins mask both
   * captures' addresses, and its tshark checks the answer's filters. The
   * caller has the statistics consent.
   */
  async compare(
    backend: BackendClient,
    req: {
      before: unknown;
      after: unknown;
      names: [string, string];
      open: "before" | "after";
      question: string;
    },
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const model = await this.readyModel();
    if (!("sendRequest" in model)) {
      return model;
    }
    try {
      const diff = await backend.request<CaptureDiff>("compare_profiles", {
        before: req.before,
        after: req.after,
        names: req.names,
      });
      const prompt = buildComparePrompt({ question: req.question, diff, open: req.open });
      this.log.info(`AI compare: ${prompt.length} characters to ${modelLabel(model)}`);
      const answer = await this.streamAnswer(
        model,
        prompt,
        COMPARE_JUSTIFICATION,
        sink,
        token,
        this.maskerFor(backend),
      );
      return {
        frames: [],
        filters: await this.validFilters(backend, extractFilters(answer), "comparison"),
      };
    } catch (err) {
      return this.failed(err, token);
    }
  }

  /**
   * Triage the capture (aiTriage.ts): tshark counts the fixed checks
   * (`triage`), the model ranks findings from them, the expert information,
   * the protocol hierarchy and the top conversations. Its filters are
   * validated (an invalid one is dropped from its finding); one retry when
   * the answer isn't the JSON asked for. The caller has the statistics consent.
   */
  async triage(
    backend: BackendClient,
    question: string,
    sink: Pick<ExplainSink, "progress">,
    token: vscode.CancellationToken,
  ): Promise<TriageOutcome> {
    const model = await this.readyModel();
    if (!("sendRequest" in model)) {
      return model;
    }
    try {
      sink.progress("Counting the checks with tshark…");
      const input = await untilCancelled(
        gatherTriage(request(backend), question, (kind, message) =>
          this.log.info(`AI triage: ${kind} statistics failed: ${message}`),
        ),
        token,
      );
      sink.progress("Asking the language model…");
      const ask = askFor(model, this.maskerFor(backend), TRIAGE_JUSTIFICATION, token);
      const turns: ChatTurn[] = [{ role: "user", content: buildTriagePrompt(input) }];
      let answer = await ask(turns);
      let report = parseTriage(answer, input);
      if (!report) {
        turns.push({ role: "assistant", content: answer }, { role: "user", content: TRIAGE_RETRY });
        answer = await ask(turns);
        report = parseTriage(answer, input);
      }
      if (!report) {
        return {
          frames: [],
          filters: [],
          checks: input.checks,
          message: "The language model's answer couldn't be read as findings. Try again.",
        };
      }
      sink.progress("Checking the filters with tshark…");
      const valid = new Set(
        await this.validFilters(
          backend,
          [...new Set(report.findings.flatMap((f) => (f.filter ? [f.filter] : [])))],
          "triage",
        ),
      );
      report.findings = report.findings.map((f) =>
        f.filter && !valid.has(f.filter) ? { ...f, filter: undefined } : f,
      );
      return {
        report,
        checks: input.checks,
        model: modelLabel(model),
        frames: [...new Set(report.findings.flatMap((f) => f.frames.slice(0, 1)))],
        filters: [...valid],
      };
    } catch (err) {
      return this.failed(err, token);
    }
  }

  /**
   * Explain expert information rows or a TCP stream (aiAnomaly.ts): the rows
   * and their conversation's statistics, or the stream's derived facts and a
   * sample of its points (never payloads). The caller has the statistics consent.
   */
  async explainAnomaly(
    backend: BackendClient,
    req: AnomalyRequest,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const model = await this.readyModel();
    if (!("sendRequest" in model)) {
      return model;
    }
    try {
      let prompt: string;
      let frames: number[] = [];
      if (req.target.kind === "call") {
        if (!req.call) {
          return {
            frames: [],
            filters: [],
            message:
              "That call is no longer available: use Ask Copilot… in the VoIP Calls panel again.",
          };
        }
        // (The parties' SIP URIs name people and hosts: stand-ins for them too.)
        this.maskerFor(backend).learnNames([{ name: req.call.from }, { name: req.call.to }]);
        prompt = buildCallPrompt({ question: req.question, call: req.call });
        frames = [
          ...new Set([
            ...req.call.problems.flatMap((p) => (p.frame === null ? [] : [p.frame])),
            ...req.call.messages.slice(0, 1).map((m) => m[0]),
          ]),
        ].slice(0, 3);
      } else if (req.target.kind === "stream") {
        sink.progress(`Reading TCP stream ${req.target.stream}…`);
        const graph = await untilCancelled(
          backend.request<{ stream: number; endpoints: string[]; points: TcpPoint[] }>(
            "tcp_graph",
            { stream: req.target.stream },
            { timeoutMs: 0 },
          ),
          token,
        );
        if (!graph.points.length) {
          return {
            frames: [],
            filters: [],
            message: `The capture has no TCP stream ${req.target.stream}.`,
          };
        }
        prompt = buildTcpPrompt({
          question: req.question,
          stream: graph.stream,
          endpoints: graph.endpoints,
          points: graph.points,
        });
      } else {
        const overview = !req.rows?.length;
        let rows = req.rows ?? [];
        if (overview) {
          sink.progress("Reading the expert information…");
          const table = await untilCancelled(
            backend.request<StatsTable>("stats", { kind: "expert" }, { timeoutMs: 0 }),
            token,
          );
          rows = notableExpertRows(expertRowsFromTable(table), ANOMALY_LIMITS.maxExpertRows);
        }
        if (!rows.length) {
          return {
            frames: [],
            filters: [],
            message: "This capture has no expert information entries.",
          };
        }
        sink.progress("Reading the conversations of these packets…");
        const conversations = await untilCancelled(this.expertConversations(backend, rows), token);
        prompt = buildExpertPrompt({
          question: req.question,
          currentFilter: req.currentFilter,
          rows,
          conversations,
          overview,
        });
        frames = [...new Set(rows.flatMap((r) => r.frames.slice(0, 1)))].slice(0, 3);
      }
      const answer = await this.streamAnswer(
        model,
        prompt,
        ANOMALY_JUSTIFICATION,
        sink,
        token,
        this.maskerFor(backend),
      );
      return {
        frames,
        filters: await this.validFilters(backend, extractFilters(answer), "anomaly"),
      };
    } catch (err) {
      return this.failed(err, token);
    }
  }

  /**
   * The whole conversations that expert rows' packets belong to: which
   * conversations those packets are in (a pass limited to them), then those
   * conversations' full statistics (a pass limited to their filters).
   */
  private async expertConversations(
    backend: BackendClient,
    rows: ExpertRow[],
  ): Promise<StatsTable | undefined> {
    const protocols = rows.map((r) => r.protocol.toLowerCase());
    const type = protocols.includes("tcp")
      ? "tcp"
      : protocols.some((p) => /udp|dns|quic/.test(p))
        ? "udp"
        : "ip";
    const flagged = framesFilter(rows, ANOMALY_LIMITS.maxFramesPerRow);
    if (!flagged) {
      return undefined;
    }
    try {
      const involved = await backend.request<StatsTable>(
        "stats",
        { kind: "conversations", type, filter: flagged },
        { timeoutMs: 0 },
      );
      const filters = involved.rows
        .map((r) => r.filter)
        .filter((f): f is string => !!f)
        .slice(0, ANOMALY_LIMITS.maxConversations);
      if (!filters.length) {
        return involved;
      }
      return await backend.request<StatsTable>(
        "stats",
        { kind: "conversations", type, filter: filters.map((f) => `(${f})`).join(" || ") },
        { timeoutMs: 0 },
      );
    } catch (err) {
      this.log.info(`AI anomaly: conversation statistics failed: ${(err as Error).message}`);
      return undefined;
    }
  }

  /** Whether this VS Code has the language model tools API (@pcap then answers with tools). */
  toolsAvailable(): boolean {
    return !!toolsRuntime();
  }

  /**
   * Answer a question about the capture with read-only tools (aiTools.ts):
   * the model calls them (at most TOOL_LIMITS.maxCalls, within
   * TOOL_LIMITS.timeLimitMs), each checking `consent`, and the answer streams
   * into `sink`. Filters the tools ran or the answer suggests become buttons.
   */
  async answerWithTools(
    backend: BackendClient,
    req: { question: string; currentFilter: string; consent: ToolConsent },
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const runtime = toolsRuntime();
    if (!runtime) {
      return {
        frames: [],
        filters: [],
        unavailable: true,
        message: "This VS Code has no language model tools.",
      };
    }
    const model = await this.readyModel();
    if (!("sendRequest" in model)) {
      return model;
    }
    // A hard stop a little after the loop's own time limit (a model round can't be interrupted otherwise).
    const deadline = new vscode.CancellationTokenSource();
    const timer = setTimeout(() => deadline.cancel(), TOOL_LIMITS.timeLimitMs + 30_000);
    const sub = token.onCancellationRequested(() => deadline.cancel());
    try {
      sink.progress("Looking into the capture…");
      const outcome = await runToolLoop(
        maskedLoopModel(
          runtime.loopModel(model, TOOLS_JUSTIFICATION, deadline.token),
          this.maskerFor(backend),
        ),
        buildToolPrompt(req.question, req.currentFilter),
        {
          cancelled: () => deadline.token.isCancellationRequested,
          onText: (t) => sink.markdown(t),
          onToolCall: (name, input) => sink.progress(describeToolCall(name, input)),
          runTool: async (name, input) => {
            const result = await runTool(name, input, backend, req.consent);
            this.maskerFor(backend).learnNames(result.names ?? []);
            return result;
          },
        },
      );
      for (const call of outcome.calls) {
        this.log.info(
          `AI tool ${call.name} ${JSON.stringify(call.input)}: ${call.result.text.split("\n")[0]}`,
        );
      }
      return {
        frames: [],
        filters: await this.validFilters(backend, outcome.filters, "tools"),
        refused: outcome.refused,
        message:
          outcome.stopped === "calls"
            ? `Stopped after ${TOOL_LIMITS.maxCalls} tool calls.`
            : outcome.stopped === "time"
              ? "Stopped at the time limit."
              : outcome.stopped === "cancelled" && !token.isCancellationRequested
                ? "Stopped at the time limit."
                : undefined,
      };
    } catch (err) {
      return this.failed(err, token);
    } finally {
      clearTimeout(timer);
      sub.dispose();
      deadline.dispose();
    }
  }

  /** Protocol names from the capture's protocol hierarchy (names only, no counts or data). */
  private protocolNames(backend: BackendClient): Promise<string[]> {
    let names = this.protocols.get(backend);
    if (!names) {
      names = backend
        .request<{ rows: { cells: unknown[] }[] }>("stats", { kind: "phs" }, { timeoutMs: 0 })
        .then((t) => [...new Set(t.rows.map((r) => String(r.cells[0] ?? "")).filter(Boolean))])
        .catch(() => {
          this.protocols.delete(backend);
          return [];
        });
      this.protocols.set(backend, names);
    }
    return names;
  }

  /** Field names/descriptions from tshark's field list, by prefix search on the request's words. */
  private async candidateFields(backend: BackendClient, request: string): Promise<FieldInfo[]> {
    type Found = {
      protocols: { name: string; desc?: string }[];
      fields: { name: string; desc?: string; blurb?: string; type?: string }[];
    };
    const lists = await Promise.all(
      extractKeywords(request).map((prefix) =>
        backend
          .request<Found>("field_index", { prefix, limit: FIELDS_PER_KEYWORD })
          .catch(() => undefined),
      ),
    );
    const out = new Map<string, FieldInfo>();
    for (const found of lists) {
      for (const p of found?.protocols ?? []) {
        out.set(p.name, { name: p.name, desc: p.desc, type: "protocol" });
      }
      for (const f of found?.fields ?? []) {
        out.set(f.name, {
          name: f.name,
          desc: f.blurb && f.blurb !== f.desc ? `${f.desc} — ${f.blurb}` : f.desc,
          type: f.type,
        });
      }
    }
    return [...out.values()];
  }

  dispose(): void {
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
