import * as path from "node:path";
import * as vscode from "vscode";
import type { BackendClient } from "../backendClient";
import { FILE_ARGS, captureFileName, captureLimits, fileCheck, fileParams } from "../captureModel";
import { getSetting, readSettings, updateSetting } from "../config";
import {
  ExtcapArg,
  ExtcapValues,
  argName,
  captureOptions,
  groupArgs,
  initialValues,
  isBoolean,
  isChoice,
  isSecret,
  missingRequired,
  storableValues,
  validateValue,
  valueLabel,
} from "../extcapModel";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import type { SavedFilter } from "../settingsModel";
import { newTemporaryCapture } from "../tempCaptures";
import { requireSession } from "./filter";
import { revealFile } from "./reveal";
import { withBackend } from "./withBackend";

const LAST_INTERFACES = "pcapViewer.capture.lastInterfaces";
const LAST_FILTER = "pcapViewer.capture.lastFilter";
/** Each extcap interface's last options (passwords never: they stay in memory). */
const EXTCAP_VALUES = "pcapViewer.capture.extcap";
const FILE_VALUES = "pcapViewer.capture.fileOptions";
const LAST_FOLDER = "pcapViewer.capture.lastFolder";
const secrets = new Map<string, ExtcapValues>();

interface CaptureInterface {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
  extcap?: boolean;
  helper?: string;
}

interface CaptureChoice {
  interfaces: string[];
  labels: string[];
  filter: string;
  extcap?: Record<string, ExtcapValues>;
}

/** An interface's name for people: its friendly name ("Ethernet 2"), else its name. */
function label(i: CaptureInterface): string {
  return i.description || i.name;
}

async function pickInterfaces(
  context: vscode.ExtensionContext,
  interfaces: CaptureInterface[],
  title: string,
): Promise<CaptureInterface[] | undefined> {
  const last = new Set(context.globalState.get<string[]>(LAST_INTERFACES, []));
  const item = (i: CaptureInterface) => ({
    label: label(i),
    description: i.description && i.description !== i.name ? i.name : undefined,
    detail: i.extcap
      ? `${i.helper ?? "extcap"} · options are asked next`
      : [i.loopback ? "loopback" : "", ...i.addresses].filter(Boolean).join(" · ") || undefined,
    picked: last.has(i.name),
    iface: i,
  });
  const local = interfaces.filter((i) => !i.extcap);
  const remote = interfaces.filter((i) => i.extcap);
  const items: (vscode.QuickPickItem & { iface?: CaptureInterface })[] = [
    ...local.map(item),
    ...(remote.length
      ? [
          {
            label: "Capture helpers (extcap): remote machines, devices, generators",
            kind: vscode.QuickPickItemKind.Separator,
          },
          ...remote.map(item),
        ]
      : []),
  ];
  const picked = await vscode.window.showQuickPick(items, {
    title: `${title}: choose the interfaces`,
    placeHolder: "Interfaces to capture on (several can be checked)",
    canPickMany: true,
    matchOnDescription: true,
    matchOnDetail: true,
  });
  const ifaces = (picked ?? []).flatMap((p) => (p.iface ? [p.iface] : []));
  return ifaces.length ? ifaces : undefined;
}

// ---------------------------------------------------------------------------- options forms

/** Ask a new value for one option (undefined: unchanged). */
async function editValue(arg: ExtcapArg, current: string): Promise<string | undefined> {
  const title = argName(arg);
  if (isBoolean(arg)) {
    const pick = await vscode.window.showQuickPick(
      [
        { label: "On", value: "true", picked: current === "true" },
        { label: "Off", value: "false", picked: current !== "true" },
      ],
      { title, placeHolder: arg.tooltip },
    );
    return pick?.value;
  }
  if (isChoice(arg) && arg.type === "multicheck") {
    const now = new Set(current.split(",").filter(Boolean));
    const picks = await vscode.window.showQuickPick(
      arg.values.map((v) => ({ label: v.display, description: v.value, picked: now.has(v.value) })),
      { title, placeHolder: arg.tooltip, canPickMany: true },
    );
    return picks?.map((p) => p.description).join(",");
  }
  if (isChoice(arg)) {
    const other = arg.type === "editselector" ? [{ label: "Other…", value: undefined }] : [];
    const pick = await vscode.window.showQuickPick(
      [
        ...arg.values.map((v) => ({
          label: v.display,
          description: v.value === current ? "current" : v.default ? "default" : undefined,
          value: v.value as string | undefined,
        })),
        ...other,
      ],
      { title, placeHolder: arg.tooltip },
    );
    if (!pick || pick.value !== undefined) {
      return pick?.value;
    }
  }
  if (arg.type === "fileselect") {
    const choice = await vscode.window.showQuickPick(
      [
        { label: "Choose a File…", id: "choose" },
        { label: "Type a Path…", id: "type" },
        ...(current ? [{ label: "Clear", id: "clear" }] : []),
      ],
      { title, placeHolder: current || arg.tooltip },
    );
    if (choice?.id === "clear") {
      return "";
    }
    if (choice?.id === "choose") {
      const files = await vscode.window.showOpenDialog({
        title,
        canSelectMany: false,
        defaultUri: current ? vscode.Uri.file(current) : undefined,
      });
      return files?.[0]?.fsPath;
    }
    if (choice?.id !== "type") {
      return undefined;
    }
  }
  return vscode.window.showInputBox({
    title,
    prompt: arg.tooltip,
    placeHolder: arg.placeholder ?? arg.default,
    value: isSecret(arg) ? "" : current,
    password: isSecret(arg),
    validateInput: (text) => validateValue({ ...arg, required: false }, text),
  });
}

/**
 * A form as a QuickPick: Start first, then every option with its value, in
 * the helper's groups; picking an option edits it. Undefined when cancelled.
 */
async function optionsForm(
  title: string,
  args: ExtcapArg[],
  values: ExtcapValues,
  check: (values: ExtcapValues) => string | undefined = () => undefined,
): Promise<ExtcapValues | undefined> {
  type Item = vscode.QuickPickItem & { arg?: ExtcapArg; start?: boolean };
  let active: string | undefined;
  for (;;) {
    const missing = missingRequired(args, values);
    const problem = missing.length ? `Set ${missing.map(argName).join(", ")} first` : check(values);
    const items: Item[] = [
      {
        label: "$(play) Start Capture",
        description: problem ?? "",
        start: true,
      },
    ];
    for (const [group, inGroup] of groupArgs(args)) {
      items.push({ label: group || "Options", kind: vscode.QuickPickItemKind.Separator });
      for (const arg of inGroup) {
        items.push({
          label: argName(arg),
          description: valueLabel(arg, values[arg.call]),
          detail: arg.tooltip,
          arg,
        });
      }
    }
    const quick = vscode.window.createQuickPick<Item>();
    quick.title = title;
    quick.placeholder = "Pick an option to change it, then Start Capture";
    quick.matchOnDetail = true;
    quick.items = items;
    const keep = items.find((i) => i.arg?.call === active);
    if (keep) {
      quick.activeItems = [keep];
    }
    const pick = await new Promise<Item | undefined>((resolve) => {
      quick.onDidAccept(() => resolve(quick.selectedItems[0]));
      quick.onDidHide(() => resolve(undefined));
      quick.show();
    });
    quick.dispose();
    if (!pick) {
      return undefined;
    }
    if (pick.start) {
      if (problem) {
        void vscode.window.showWarningMessage(`PCAP Lens: ${problem}.`);
        continue;
      }
      return values;
    }
    if (pick.arg) {
      active = pick.arg.call;
      const value = await editValue(pick.arg, values[pick.arg.call] ?? "");
      if (value !== undefined) {
        values[pick.arg.call] = value;
      }
    }
  }
}

/** An extcap interface's options, asked with its own form (undefined: cancelled). */
async function configureExtcap(
  context: vscode.ExtensionContext,
  backend: BackendClient,
  iface: CaptureInterface,
): Promise<ExtcapValues | undefined> {
  const { args } = await backend.request<{ args: ExtcapArg[] }>(
    "extcap_config",
    { interface: iface.name },
    { timeoutMs: 30_000 },
  );
  if (!args.length) {
    return {};
  }
  const saved = context.globalState.get<Record<string, unknown>>(EXTCAP_VALUES, {});
  const values = { ...initialValues(args, saved[iface.name]), ...secrets.get(iface.name) };
  const done = await optionsForm(`Start Capture: ${label(iface)}`, args, values);
  if (!done) {
    return undefined;
  }
  await context.globalState.update(EXTCAP_VALUES, {
    ...saved,
    [iface.name]: storableValues(args, done),
  });
  secrets.set(
    iface.name,
    Object.fromEntries(args.filter(isSecret).map((a) => [a.call, done[a.call] ?? ""])),
  );
  return captureOptions(args, done);
}

// ---------------------------------------------------------------------------- capture filter

function savedCaptureFilters(): SavedFilter[] {
  return readSettings().captureFilters;
}

/**
 * The capture filter, checked by dumpcap as it is typed, with buttons for the
 * saved capture filters and to save this one (undefined: cancelled).
 */
async function askFilter(
  context: vscode.ExtensionContext,
  backend: BackendClient,
  iface: string,
  title: string,
): Promise<string | undefined> {
  const box = vscode.window.createInputBox();
  box.title = `${title}: capture filter`;
  box.prompt = "Only packets matching this capture (BPF) filter are captured. Empty: every packet.";
  box.placeholder = "e.g. tcp port 443, host 10.0.0.1, not arp";
  box.value = context.globalState.get<string>(LAST_FILTER, "");
  const savedButton = {
    iconPath: new vscode.ThemeIcon("bookmark"),
    tooltip: "Saved Capture Filters",
  };
  const saveButton = {
    iconPath: new vscode.ThemeIcon("save"),
    tooltip: "Save This Capture Filter",
  };
  box.buttons = [savedButton, saveButton];
  let seq = 0;
  const check = async (text: string) => {
    const mine = ++seq;
    box.validationMessage = undefined;
    await new Promise((resolve) => setTimeout(resolve, 250));
    if (mine !== seq || !text.trim()) {
      return;
    }
    try {
      const res = await backend.request<{
        valid: boolean;
        checked: boolean;
        error?: string;
        message?: string;
      }>("validate_capture_filter", { filter: text, interface: iface });
      if (mine !== seq) {
        return;
      }
      if (!res.valid) {
        box.validationMessage = `Invalid capture filter: ${res.error ?? ""}`;
      } else if (!res.checked && res.message) {
        box.validationMessage = {
          message: `Couldn't check the filter: ${res.message.split("\n")[0]}`,
          severity: vscode.InputBoxValidationSeverity.Warning,
        };
      }
    } catch {
      // (checked again when capturing)
    }
  };
  void check(box.value);
  return new Promise<string | undefined>((resolve) => {
    let busy = false;
    box.onDidChangeValue((text) => void check(text));
    box.onDidAccept(() => {
      const error = box.validationMessage;
      if (typeof error === "string" && error) {
        return;
      }
      resolve(box.value.trim());
      box.dispose();
    });
    box.onDidHide(() => {
      if (!busy) {
        resolve(undefined);
        box.dispose();
      }
    });
    box.onDidTriggerButton(async (button) => {
      busy = true;
      try {
        if (button === savedButton) {
          const pick = await vscode.window.showQuickPick(
            savedCaptureFilters().map((f) => ({ label: f.name, description: f.filter, f })),
            {
              title: "Saved Capture Filters",
              placeHolder: "Use one (pcapViewer.capture.savedFilters holds them)",
              matchOnDescription: true,
            },
          );
          if (pick) {
            box.value = pick.f.filter;
            void check(box.value);
          }
        } else if (button === saveButton && box.value.trim()) {
          const name = await vscode.window.showInputBox({
            title: "Save This Capture Filter",
            prompt: box.value.trim(),
            placeHolder: "A name for it",
            validateInput: (t) => (t.trim() ? undefined : "A name, please"),
          });
          if (name?.trim()) {
            const rest = savedCaptureFilters().filter((f) => f.name !== name.trim());
            await updateSetting("capture.savedFilters", [
              ...rest,
              { name: name.trim(), filter: box.value.trim() },
            ]);
            vscode.window.setStatusBarMessage(`Saved capture filter ${name.trim()}`, 3000);
          }
        }
      } finally {
        busy = false;
        box.show();
      }
    });
    box.show();
  });
}

/** Interfaces, extcap options and the capture filter, asked in turn (undefined: cancelled). */
async function askCapture(
  context: vscode.ExtensionContext,
  backend: BackendClient,
  title: string,
): Promise<CaptureChoice | undefined> {
  const res = await backend.request<{ interfaces: CaptureInterface[] }>(
    "list_interfaces",
    {},
    { timeoutMs: 60_000 },
  );
  if (!res.interfaces.length) {
    throw new Error(
      "dumpcap lists no interfaces to capture on. It may lack the permission to see them " +
        "(see the PCAP Lens README: Live capture).",
    );
  }
  const picked = await pickInterfaces(context, res.interfaces, title);
  if (!picked) {
    return undefined;
  }
  const extcap: Record<string, ExtcapValues> = {};
  for (const iface of picked.filter((i) => i.extcap)) {
    const values = await configureExtcap(context, backend, iface);
    if (!values) {
      return undefined;
    }
    extcap[iface.name] = values;
  }
  const local = picked.filter((i) => !i.extcap);
  let filter = "";
  if (local.length) {
    const asked = await askFilter(context, backend, local[0].name, title);
    if (asked === undefined) {
      return undefined;
    }
    filter = asked;
    await context.globalState.update(LAST_FILTER, filter);
  }
  await context.globalState.update(
    LAST_INTERFACES,
    picked.map((i) => i.name),
  );
  return {
    interfaces: picked.map((i) => i.name),
    labels: picked.map(label),
    filter,
    extcap: Object.keys(extcap).length ? extcap : undefined,
  };
}

/** Options given to the command (tests, keybindings): interfaces, filter, extcap. */
function givenCapture(options?: Record<string, unknown>): CaptureChoice | undefined {
  const given = Array.isArray(options?.interfaces)
    ? options.interfaces.filter((i): i is string => typeof i === "string" && !!i)
    : [];
  if (!given.length) {
    return undefined;
  }
  const extcap =
    options?.extcap && typeof options.extcap === "object"
      ? (options.extcap as Record<string, ExtcapValues>)
      : undefined;
  return {
    interfaces: given,
    labels: given,
    filter: typeof options?.filter === "string" ? options.filter.trim() : "",
    extcap,
  };
}

function showError(log: vscode.LogOutputChannel, err: unknown): void {
  log.error(`capture: ${describeError(err)}`);
  void vscode.window
    .showErrorMessage(`PCAP Lens: ${describeError(err)}`, "Show Log")
    .then((c) => c && log.show());
}

/**
 * "PCAP: Start Capture…": choose interfaces (local ones and extcap helpers'),
 * the helpers' options and a capture filter, then a new (unsaved) capture
 * opens and fills as packets arrive. `options` skips the questions (tests,
 * keybindings with arguments).
 */
export async function startCapture(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  options?: Record<string, unknown>,
): Promise<vscode.Uri | undefined> {
  let choice: CaptureChoice | undefined = givenCapture(options);
  if (!choice) {
    try {
      choice = await withBackend(provider, context, log, (backend) =>
        askCapture(context, backend, "Start Capture"),
      );
    } catch (err) {
      showError(log, err);
      return undefined;
    }
  }
  if (!choice) {
    return undefined;
  }
  const file = await newTemporaryCapture(context, captureFileName(choice.labels, new Date()));
  const uri = vscode.Uri.file(file);
  provider.queueCapture(uri, {
    interfaces: choice.interfaces,
    labels: choice.labels,
    filter: choice.filter,
    limits: captureLimits(
      getSetting<unknown>("capture.stopAfterPackets", 0),
      getSetting<unknown>("capture.stopAfterSeconds", 0),
      getSetting<unknown>("capture.stopAfterMegabytes", 0),
    ),
    promiscuous: getSetting<boolean>("capture.promiscuous", true) !== false,
    extcap: choice.extcap,
  });
  await vscode.commands.executeCommand("vscode.openWith", uri, PcapEditorProvider.viewType);
  return uri;
}

// ---------------------------------------------------------------------------- to files

interface FileCaptureResult {
  files: string[];
  packets: number;
  seconds: number;
  dropped: number | null;
  stopped: boolean;
  error?: string;
}

const formatBytes = (n: number) =>
  n < 1_000_000 ? `${(n / 1000).toFixed(0)} kB` : `${(n / 1_000_000).toFixed(1)} MB`;

/**
 * "PCAP: Capture to Files…": like Start Capture, but dumpcap writes files in
 * a folder (Wireshark's capture output options: a new file every so many MB,
 * seconds or packets, a ring buffer, stop after N files, pcap or pcapng), with
 * no live view; the progress notification's Cancel stops it. Then the files
 * can be opened, merged or shown. `options` (`interfaces`, `folder`, `name`,
 * `format`, `files`, `limits`, `extcap`) skip the questions and return the result.
 */
async function captureToFiles(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  options?: Record<string, unknown>,
): Promise<FileCaptureResult | undefined> {
  const given = givenCapture(options);
  let result: FileCaptureResult | undefined;
  try {
    // (Its own backend: closing an editor mustn't end the capture.)
    result = await withBackend(
      provider,
      context,
      log,
      async (backend) => {
        const choice = given ?? (await askCapture(context, backend, "Capture to Files"));
        if (!choice) {
          return undefined;
        }
        let params: Record<string, unknown>;
        if (given && typeof options?.folder === "string") {
          params = {
            folder: options.folder,
            name: typeof options.name === "string" ? options.name : "capture",
            format: options.format,
            files: options.files,
            limits: options.limits,
          };
        } else {
          const last = context.globalState.get<string>(LAST_FOLDER);
          const folders = await vscode.window.showOpenDialog({
            title: "Capture to Files: the folder for the files",
            canSelectFiles: false,
            canSelectFolders: true,
            canSelectMany: false,
            openLabel: "Capture Here",
            defaultUri: last ? vscode.Uri.file(last) : vscode.workspace.workspaceFolders?.[0]?.uri,
          });
          if (!folders?.[0]) {
            return undefined;
          }
          const name = await vscode.window.showInputBox({
            title: "Capture to Files: file name",
            prompt: "dumpcap adds _00001_<date and time> when it starts new files",
            value: captureFileName(choice.labels, new Date()).replace(/_\d{4}-.*$/, ""),
            validateInput: (t) =>
              /^[^\\/:*?"<>|]+$/.test(t.trim()) ? undefined : "A file name without folders",
          });
          if (!name) {
            return undefined;
          }
          const saved = context.globalState.get<unknown>(FILE_VALUES);
          const args = FILE_ARGS;
          const values = await optionsForm(
            `Capture to Files: ${path.basename(folders[0].fsPath)}`,
            args,
            initialValues(args, saved),
            fileCheck,
          );
          if (!values) {
            return undefined;
          }
          await context.globalState.update(FILE_VALUES, storableValues(args, values));
          await context.globalState.update(LAST_FOLDER, folders[0].fsPath);
          params = { folder: folders[0].fsPath, name: name.trim(), ...fileParams(values) };
        }
        const where = String(params.folder);
        return vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: `Capturing to ${path.basename(where)}`,
            cancellable: true,
          },
          (progress, token) => {
            const pending = backend.send<FileCaptureResult>(
              "capture_to_files",
              {
                ...params,
                interfaces: choice.interfaces,
                filter: choice.filter,
                extcap: choice.extcap,
                promiscuous: getSetting<boolean>("capture.promiscuous", true) !== false,
              },
              {
                timeoutMs: 0,
                onProgress: (p) => {
                  const q = p as { packets?: number; files?: number; bytes?: number };
                  progress.report({
                    message:
                      `${(q.packets ?? 0).toLocaleString()} packets · ${q.files ?? 0} ` +
                      `${q.files === 1 ? "file" : "files"} · ${formatBytes(q.bytes ?? 0)} ` +
                      "(Cancel stops the capture)",
                  });
                },
              },
            );
            token.onCancellationRequested(() => {
              void backend.request("capture_files_stop", {}).catch(() => undefined);
            });
            return pending.promise;
          },
        );
      },
      { own: true },
    );
  } catch (err) {
    showError(log, err);
    return undefined;
  }
  if (!result || given) {
    return result;
  }
  const files = result.files;
  const summary =
    `Captured ${result.packets.toLocaleString()} packets into ${files.length} ` +
    `${files.length === 1 ? "file" : "files"}` +
    (result.dropped ? ` (${result.dropped.toLocaleString()} dropped)` : "") +
    (result.error ? `: ${result.error}` : ".");
  const open = files.length === 1 ? "Open" : "Open Latest";
  const merge = "Merge and Open";
  const reveal = "Show Files";
  const pick = await vscode.window.showInformationMessage(
    `PCAP Lens: ${summary}`,
    ...(files.length ? [open] : []),
    ...(files.length > 1 ? [merge] : []),
    ...(files.length ? [reveal] : []),
  );
  if (pick === open) {
    await vscode.commands.executeCommand(
      "vscode.openWith",
      vscode.Uri.file(files[files.length - 1]),
      PcapEditorProvider.viewType,
    );
  } else if (pick === merge) {
    await vscode.commands.executeCommand("pcapViewer.mergeCaptures", files);
  } else if (pick === reveal) {
    await revealFile(files[files.length - 1]);
  }
  return result;
}

export function registerCaptureCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  const asOptions = (options: unknown) =>
    options && typeof options === "object" ? (options as Record<string, unknown>) : undefined;
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.startCapture", (options?: unknown) =>
      startCapture(provider, context, log, asOptions(options)),
    ),
    vscode.commands.registerCommand("pcapViewer.captureToFiles", (options?: unknown) =>
      captureToFiles(provider, context, log, asOptions(options)),
    ),
    vscode.commands.registerCommand("pcapViewer.stopCapture", async () => {
      const session = requireSession(provider);
      if (session && !session.capturing) {
        void vscode.window.showInformationMessage("This capture is not running.");
        return;
      }
      await session?.stopCapture();
    }),
  );
}
