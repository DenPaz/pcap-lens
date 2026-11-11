/**
 * Remote windows (WSL, SSH, Dev Containers, Codespaces, tunnels): the
 * extension runs where the files are (`extensionKind: ["workspace"]`), and so
 * do Python, tshark and dumpcap. Pure helpers (no `vscode` import) for the
 * few places where that shows.
 */

/** Where the extension (and so tshark) runs, for messages: `vscode.env.remoteName`. */
export function whereLabel(remoteName: string | undefined): string | undefined {
  switch (remoteName) {
    case undefined:
    case "":
      return undefined;
    case "wsl":
      return "WSL";
    case "ssh-remote":
      return "the SSH host";
    case "dev-container":
    case "attached-container":
      return "the container";
    case "codespaces":
      return "the codespace";
    case "tunnel":
      return "the tunnel's machine";
    default:
      return `the remote machine (${remoteName})`;
  }
}

/**
 * How to show a file: the OS file manager only works for local files;
 * remotely, the Explorer view when the file is in the workspace, else its
 * path. `preferExplorer`: the Explorer view locally too, when it can.
 */
export function revealHow(
  remoteName: string | undefined,
  inWorkspace: boolean,
  preferExplorer = false,
): "os" | "explorer" | "copyPath" {
  if (inWorkspace && (preferExplorer || whereLabel(remoteName))) {
    return "explorer";
  }
  return whereLabel(remoteName) ? "copyPath" : "os";
}

/** tshark reads files: only `file:` documents can be opened directly. */
export function isOnDisk(uri: { scheme: string }): boolean {
  return uri.scheme === "file";
}

/** Bytes in a megabyte, as the size settings count them. */
const MB = 1024 * 1024;

/**
 * Whether a capture that isn't on disk opens as a copy without asking:
 * `pcapViewer.virtualFiles.autoCopyMB` (0 = always ask), against its size
 * (unknown = ask, so a huge file isn't read into memory unasked).
 */
export function copiesAutomatically(size: number | undefined, limitMB: number): boolean {
  return (
    limitMB > 0 && size !== undefined && Number.isFinite(size) && size >= 0 && size <= limitMB * MB
  );
}

/** A size in the settings' megabytes: "300.5 MB". */
export function formatMB(bytes: number): string {
  return `${(bytes / MB).toFixed(1)} MB`;
}

/** The file name for a copy of a capture that isn't on disk (`vsls:`, zip, virtual file systems). */
export function copyName(uri: { path: string }): string {
  const base = uri.path.split("/").filter(Boolean).pop() ?? "";
  // Characters Windows refuses in file names, and control characters.
  const safe = [...base]
    .map((c) => (c < " " || '\\/:*?"<>|'.includes(c) ? "_" : c))
    .join("")
    .trim();
  return safe || "capture.pcapng";
}
