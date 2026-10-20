import * as path from "node:path";
import * as vscode from "vscode";
import { readSettings } from "../config";
import {
  DecryptionKey,
  ESP_AUTHENTICATION,
  ESP_ENCRYPTION,
  KEY_TYPES,
  KeyType,
  keyLabel,
  keysDigest,
  normalizeKeys,
  typeLabel,
  validate,
  withKey,
} from "../decryptionKeys";
import type { PcapEditorProvider } from "../pcapEditor";

const SECRET = "pcapViewer.decryptionKeys";

/**
 * The decryption keys, kept in VS Code's secret storage (one JSON list for
 * every capture). Loading starts at activation; a capture's load awaits
 * `ready` before reading `all`. `onDidChange` fires when the list changes
 * here or in another window.
 */
class KeyStore {
  private keys: DecryptionKey[] = [];
  private secrets?: vscode.SecretStorage;
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.emitter.event;
  /** Resolves once the stored keys are loaded (never rejects). */
  ready: Promise<void> = Promise.resolve();

  init(context: vscode.ExtensionContext): void {
    this.secrets = context.secrets;
    this.ready = this.load();
    context.subscriptions.push(
      this.emitter,
      context.secrets.onDidChange((e) => {
        if (e.key === SECRET) {
          void this.load();
        }
      }),
    );
  }

  get all(): readonly DecryptionKey[] {
    return this.keys;
  }

  async set(keys: DecryptionKey[]): Promise<void> {
    if (!this.secrets) {
      throw new Error("the key store isn't ready");
    }
    const changed = keysDigest(keys) !== keysDigest(this.keys);
    this.keys = keys;
    try {
      if (keys.length) {
        await this.secrets.store(SECRET, JSON.stringify(keys));
      } else {
        await this.secrets.delete(SECRET);
      }
    } catch (err) {
      // (No OS keyring, say: the keys still apply until VS Code closes.)
      void vscode.window.showWarningMessage(
        `PCAP Lens: the decryption keys couldn't be saved (${String(err)}); they apply until VS Code closes.`,
      );
    }
    if (changed) {
      this.emitter.fire();
    }
  }

  private async load(): Promise<void> {
    let keys: DecryptionKey[];
    try {
      const raw = await this.secrets?.get(SECRET);
      keys = raw ? normalizeKeys(JSON.parse(raw)) : [];
    } catch {
      keys = [];
    }
    if (keysDigest(keys) !== keysDigest(this.keys)) {
      this.keys = keys;
      this.emitter.fire();
    }
  }
}

export const keyStore = new KeyStore();

type Row = vscode.QuickPickItem & { action: "add" | "key" | "tls"; index?: number };

/**
 * _PCAP: Decryption Keys…_: Wi-Fi (WEP, WPA passphrases and PSKs), TLS RSA
 * private keys, SSH and WireGuard key logs, IPsec ESP security associations
 * and Kerberos keytabs, for every capture (the TLS key log keeps its own
 * setting and command, listed here too). Changing them reloads the open
 * captures (extension.ts). `{keys}` replaces the list and `{quiet: true}`
 * returns it, without asking (smoke test).
 */
export function registerDecryptionCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  keyStore.init(context);
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pcapViewer.decryptionKeys",
      async (args?: { keys?: unknown; quiet?: boolean }): Promise<unknown> => {
        if (args?.keys !== undefined) {
          await keyStore.set(normalizeKeys(args.keys));
          return keyStore.all;
        }
        if (args?.quiet) {
          return keyStore.all.map(keyLabel);
        }
        await manageKeys(provider);
        return undefined;
      },
    ),
  );
}

async function manageKeys(provider: PcapEditorProvider): Promise<void> {
  for (;;) {
    const keyLog = readSettings(provider.activeSession?.uri).tlsKeyLogFile;
    const rows: Row[] = [
      { label: "$(add) Add a Key…", action: "add" },
      ...keyStore.all.map((k, index): Row => ({
        label: keyLabel(k),
        description: typeLabel(k.type),
        action: "key",
        index,
      })),
      { label: "", kind: vscode.QuickPickItemKind.Separator, action: "tls" },
      {
        label: "$(key) TLS Key Log File…",
        description: keyLog ? path.basename(keyLog) : "not set",
        detail: "TLS and QUIC session keys (SSLKEYLOGFILE), set per workspace",
        action: "tls",
      },
    ];
    const pick = await vscode.window.showQuickPick(rows, {
      title: "Decryption Keys",
      placeHolder: keyStore.all.length
        ? "Pick a key to change or remove it, or add one"
        : "No keys yet: add one (tshark also uses Wireshark's own key tables)",
    });
    if (!pick) {
      return;
    }
    if (pick.action === "tls") {
      await vscode.commands.executeCommand("pcapViewer.setTlsKeyLogFile");
      return;
    }
    if (pick.action === "add") {
      const type = await vscode.window.showQuickPick(
        KEY_TYPES.map((t) => ({ label: t.label, detail: t.detail, type: t.type })),
        { title: "Add a Decryption Key", placeHolder: "What kind of key?" },
      );
      const key = type && (await askKey(type.type));
      if (key) {
        await keyStore.set(withKey(keyStore.all, key));
      }
      continue;
    }
    const index = pick.index!;
    const current = keyStore.all[index];
    const action = await vscode.window.showQuickPick(
      [
        { label: "$(edit) Change…", id: "edit" },
        { label: "$(trash) Remove", id: "remove" },
      ],
      { title: keyLabel(current) },
    );
    if (action?.id === "remove") {
      await keyStore.set(keyStore.all.filter((_, i) => i !== index));
    } else if (action?.id === "edit") {
      const key = await askKey(current.type, current);
      if (key) {
        await keyStore.set(withKey(keyStore.all, key, index));
      }
    }
  }
}

async function input(
  title: string,
  prompt: string,
  check: (v: string) => string | undefined,
  options: { value?: string; password?: boolean; optional?: boolean } = {},
): Promise<string | undefined> {
  const value = await vscode.window.showInputBox({
    title,
    prompt,
    value: options.value,
    password: options.password,
    ignoreFocusOut: true,
    validateInput: (v) => (options.optional && !v.trim() ? undefined : check(v)),
  });
  return value === undefined ? undefined : value.trim();
}

async function pickFile(
  title: string,
  filters: Record<string, string[]>,
): Promise<string | undefined> {
  const chosen = await vscode.window.showOpenDialog({
    title,
    canSelectMany: false,
    filters: { ...filters, "All files": ["*"] },
  });
  return chosen?.[0]?.fsPath;
}

/** Ask for a key of `type` (starting from `old` when changing one). */
async function askKey(type: KeyType, old?: DecryptionKey): Promise<DecryptionKey | undefined> {
  const title = typeLabel(type);
  const prev = (old ?? {}) as Partial<Record<string, string>>;
  switch (type) {
    case "wep":
    case "wpa-psk": {
      const sizes = type === "wep" ? [5, 13, 16] : [32];
      const key = await input(
        title,
        type === "wep" ? "The WEP key in hexadecimal" : "The 256-bit pre-shared key in hexadecimal",
        (v) => validate.hex(v, sizes),
        { value: prev.key, password: true },
      );
      return key ? { type, key } : undefined;
    }
    case "wpa-pwd": {
      const password = await input(title, "The network's passphrase", validate.passphrase, {
        value: prev.password,
        password: true,
      });
      if (!password) {
        return undefined;
      }
      const ssid = await input(
        title,
        "The network's name (SSID); empty tries the passphrase on every network",
        validate.ssid,
        { value: prev.ssid, optional: true },
      );
      return ssid === undefined ? undefined : { type, password, ssid: ssid || undefined };
    }
    case "rsa": {
      const file = await pickFile("TLS RSA private key", {
        "Private keys": ["pem", "key", "p12", "pfx"],
      });
      if (!file) {
        return undefined;
      }
      const password = await input(
        title,
        "The key file's password (PKCS#12), or empty",
        () => undefined,
        { password: true, optional: true },
      );
      return password === undefined ? undefined : { type, file, password: password || undefined };
    }
    case "ssh":
    case "wireguard":
    case "kerberos": {
      const file = await pickFile(
        title,
        type === "kerberos" ? { Keytabs: ["keytab"] } : { "Key logs": ["log", "txt", "keys"] },
      );
      return file ? { type, file } : undefined;
    }
    case "esp":
      return askEsp(old?.type === "esp" ? old : undefined);
  }
}

async function askEsp(
  old?: Extract<DecryptionKey, { type: "esp" }>,
): Promise<DecryptionKey | undefined> {
  const title = "IPsec ESP security association";
  const protocol = await vscode.window.showQuickPick(["IPv4", "IPv6"], {
    title,
    placeHolder: `Protocol${old ? ` (now ${old.protocol})` : ""}`,
  });
  if (protocol !== "IPv4" && protocol !== "IPv6") {
    return undefined;
  }
  const src = await input(title, "Source address (or a prefix, or *)", validate.address, {
    value: old?.src ?? "*",
  });
  const dst =
    src &&
    (await input(title, "Destination address (or a prefix, or *)", validate.address, {
      value: old?.dst ?? "*",
    }));
  const spi =
    dst &&
    (await input(title, "SPI, e.g. 0x00000100 (or *)", validate.spi, {
      value: old?.spi ?? "*",
    }));
  if (!src || !dst || !spi) {
    return undefined;
  }
  const encryption = await vscode.window.showQuickPick([...ESP_ENCRYPTION], {
    title,
    placeHolder: `Encryption${old ? ` (now ${old.encryption})` : ""}`,
  });
  if (!encryption) {
    return undefined;
  }
  const hexKey = (v: string) => validate.hex(v, []);
  const encryptionKey =
    encryption === "NULL"
      ? ""
      : await input(
          title,
          `${encryption} key in hexadecimal (AES-CTR and AES-GCM: with the 4-byte salt)`,
          hexKey,
          {
            value: old?.encryptionKey,
            password: true,
          },
        );
  if (encryptionKey === undefined) {
    return undefined;
  }
  const authentication = await vscode.window.showQuickPick([...ESP_AUTHENTICATION], {
    title,
    placeHolder: `Authentication${old ? ` (now ${old.authentication})` : ""}`,
  });
  if (!authentication) {
    return undefined;
  }
  const authenticationKey =
    authentication === "NULL" || authentication.startsWith("ANY ")
      ? ""
      : await input(title, `${authentication} key in hexadecimal`, hexKey, {
          value: old?.authenticationKey,
          password: true,
        });
  if (authenticationKey === undefined) {
    return undefined;
  }
  return {
    type: "esp",
    protocol,
    src,
    dst,
    spi,
    encryption,
    encryptionKey: encryptionKey || undefined,
    authentication,
    authenticationKey: authenticationKey || undefined,
  };
}
