/**
 * Decryption keys (pure): what _PCAP: Decryption Keys…_ stores and how each
 * key is shown. The backend turns them into tshark options (decryption.py)
 * and checks every value again; the TLS key log stays its own setting
 * (`pcapViewer.tlsKeyLogFile`), since browsers and curl write one per
 * project.
 *
 * Keys live in VS Code's secret storage (they hold passphrases and keys), for
 * every capture, like Wireshark's own key tables.
 */

export type DecryptionKey =
  | { type: "wep"; key: string }
  | { type: "wpa-pwd"; password: string; ssid?: string }
  | { type: "wpa-psk"; key: string }
  | { type: "rsa"; file: string; password?: string }
  | { type: "ssh" | "wireguard" | "kerberos"; file: string }
  | {
      type: "esp";
      protocol: "IPv4" | "IPv6";
      src: string;
      dst: string;
      spi: string;
      encryption: string;
      encryptionKey?: string;
      authentication: string;
      authenticationKey?: string;
    };

export type KeyType = DecryptionKey["type"];

export const KEY_TYPES: readonly { type: KeyType; label: string; detail: string }[] = [
  {
    type: "wpa-pwd",
    label: "Wi-Fi WPA/WPA2 passphrase",
    detail: "The network's password and name (SSID)",
  },
  { type: "wpa-psk", label: "Wi-Fi WPA/WPA2 pre-shared key", detail: "64 hexadecimal digits" },
  { type: "wep", label: "Wi-Fi WEP key", detail: "10, 26 or 32 hexadecimal digits" },
  {
    type: "rsa",
    label: "TLS RSA private key",
    detail: "A PEM or PKCS#12 file (RSA key exchange only, not TLS 1.3)",
  },
  { type: "ssh", label: "SSH key log", detail: "A file of session keys (one per preference)" },
  { type: "wireguard", label: "WireGuard key log", detail: "A file of static and ephemeral keys" },
  {
    type: "esp",
    label: "IPsec ESP security association",
    detail: "Addresses, SPI, algorithms and keys",
  },
  { type: "kerberos", label: "Kerberos keytab", detail: "A keytab file" },
];

/** The values tshark's esp_sa table takes (decryption.py lists the same). */
export const ESP_ENCRYPTION = [
  "NULL",
  "TripleDES-CBC [RFC2451]",
  "AES-CBC [RFC3602]",
  "AES-CTR [RFC3686]",
  "DES-CBC [RFC2405]",
  "CAST5-CBC [RFC2144]",
  "BLOWFISH-CBC [RFC2451]",
  "TWOFISH-CBC",
  "AES-GCM with 8 octet ICV [RFC4106]",
  "AES-GCM with 12 octet ICV [RFC4106]",
  "AES-GCM with 16 octet ICV [RFC4106]",
] as const;
export const ESP_AUTHENTICATION = [
  "NULL",
  "HMAC-SHA-1-96 [RFC2404]",
  "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]",
  "HMAC-SHA-256-128 [RFC4868]",
  "HMAC-SHA-384-192 [RFC4868]",
  "HMAC-SHA-512-256 [RFC4868]",
  "HMAC-MD5-96 [RFC2403]",
  "MAC-RIPEMD-160-96 [RFC2857]",
  "ANY 64 bit authentication [no checking]",
  "ANY 96 bit authentication [no checking]",
  "ANY 128 bit authentication [no checking]",
  "ANY 192 bit authentication [no checking]",
  "ANY 256 bit authentication [no checking]",
] as const;

const FILE_TYPES = new Set<string>(["rsa", "ssh", "wireguard", "kerberos"]);
/** Key types tshark takes one file of (a preference, not a table). */
export const ONE_FILE_TYPES: ReadonlySet<KeyType> = new Set(["ssh", "wireguard", "kerberos"]);

const str = (v: unknown) => (typeof v === "string" ? v : "");

/** The stored list, checked loosely (the backend refuses bad values with a message). */
export function normalizeKeys(raw: unknown): DecryptionKey[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: DecryptionKey[] = [];
  for (const item of raw as unknown[]) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const o = item as Record<string, unknown>;
    switch (o.type) {
      case "wep":
      case "wpa-psk":
        if (str(o.key)) {
          out.push({ type: o.type, key: str(o.key) });
        }
        break;
      case "wpa-pwd":
        if (str(o.password)) {
          out.push({ type: "wpa-pwd", password: str(o.password), ssid: str(o.ssid) || undefined });
        }
        break;
      case "rsa":
        if (str(o.file)) {
          out.push({ type: "rsa", file: str(o.file), password: str(o.password) || undefined });
        }
        break;
      case "ssh":
      case "wireguard":
      case "kerberos":
        if (str(o.file)) {
          out.push({ type: o.type, file: str(o.file) });
        }
        break;
      case "esp":
        out.push({
          type: "esp",
          protocol: o.protocol === "IPv6" ? "IPv6" : "IPv4",
          src: str(o.src) || "*",
          dst: str(o.dst) || "*",
          spi: str(o.spi) || "*",
          encryption: str(o.encryption) || "NULL",
          encryptionKey: str(o.encryptionKey) || undefined,
          authentication: str(o.authentication) || "NULL",
          authenticationKey: str(o.authenticationKey) || undefined,
        });
        break;
    }
  }
  return out;
}

/** The type's label ("Wi-Fi WEP key"). */
export function typeLabel(type: KeyType): string {
  return KEY_TYPES.find((t) => t.type === type)?.label ?? type;
}

/** A hex key shown without its value: its first two bytes and its length. */
function maskedHex(hex: string): string {
  const digits = hex.replace(/^0x/i, "").replace(/[\s:-]/g, "");
  return digits.length >= 4
    ? `${digits.slice(0, 4)}… (${Math.floor(digits.length / 2)} bytes)`
    : "(set)";
}

/** One line naming the key without giving its secret away. */
export function keyLabel(key: DecryptionKey): string {
  const base = (p: string) => p.split(/[\\/]/).pop() || p;
  switch (key.type) {
    case "wep":
      return `WEP key ${maskedHex(key.key)}`;
    case "wpa-psk":
      return `WPA pre-shared key ${maskedHex(key.key)}`;
    case "wpa-pwd":
      return key.ssid ? `WPA passphrase for "${key.ssid}"` : "WPA passphrase (any network)";
    case "rsa":
      return `RSA private key ${base(key.file)}${key.password ? " (with password)" : ""}`;
    case "ssh":
      return `SSH key log ${base(key.file)}`;
    case "wireguard":
      return `WireGuard key log ${base(key.file)}`;
    case "kerberos":
      return `Kerberos keytab ${base(key.file)}`;
    case "esp":
      return `ESP SA ${key.src} → ${key.dst}, SPI ${key.spi} (${key.encryption.replace(/ \[.*\]$/, "")})`;
  }
}

/** The file a key names, if any. */
export function keyFile(key: DecryptionKey): string | undefined {
  return FILE_TYPES.has(key.type) ? (key as { file: string }).file : undefined;
}

/** A stable text of the list, to compare the keys a capture was loaded with. */
export function keysDigest(keys: readonly DecryptionKey[]): string {
  return JSON.stringify(keys);
}

/**
 * The list with `key` added (or put in place of `replacing`): a file-type
 * key tshark takes one of replaces the one of its type, and an identical key
 * isn't added twice.
 */
export function withKey(
  keys: readonly DecryptionKey[],
  key: DecryptionKey,
  replacing?: number,
): DecryptionKey[] {
  const out: DecryptionKey[] = [];
  keys.forEach((k, i) => {
    if (i === replacing) {
      out.push(key);
    } else if (
      keysDigest([k]) !== keysDigest([key]) &&
      !(ONE_FILE_TYPES.has(key.type) && k.type === key.type)
    ) {
      out.push(k);
    }
  });
  if (replacing === undefined || replacing >= keys.length) {
    out.push(key);
  }
  return out;
}

/** Checks of what the user types (undefined = fine), like the backend's. */
export const validate = {
  hex(value: string, sizes: readonly number[]): string | undefined {
    const digits = value
      .trim()
      .replace(/^0x/i, "")
      .replace(/[\s:-]/g, "");
    if (!/^[0-9a-fA-F]*$/.test(digits) || digits.length % 2) {
      return "Hexadecimal digits, two per byte (colons and spaces are fine)";
    }
    if (sizes.length && !sizes.includes(digits.length / 2)) {
      return `${sizes.map((n) => n * 2).join(", ")} hexadecimal digits`;
    }
    return undefined;
  },
  passphrase(value: string): string | undefined {
    return value.length >= 8 && value.length <= 63 && /^[\x20-\x7e]*$/.test(value)
      ? undefined
      : "8 to 63 printable ASCII characters";
  },
  ssid(value: string): string | undefined {
    return new TextEncoder().encode(value).length <= 32 ? undefined : "At most 32 bytes";
  },
  address(value: string): string | undefined {
    return /^[0-9a-fA-F:.*/]{1,64}$/.test(value.trim() || "*")
      ? undefined
      : "An IPv4 or IPv6 address, a prefix (10.0.0.0/8) or *";
  },
  spi(value: string): string | undefined {
    return /^(\*|0x[0-9a-fA-F]{1,8}|\d{1,10})$/.test(value.trim() || "*")
      ? undefined
      : "* or a number such as 0x00000100";
  },
};
