/**
 * Which capture file a language model tool's `capture` argument names (the
 * file a user attached with `#file:`/`@file:`, or named in chat), and whether
 * the tools may read it. No `vscode` import: unit-tested; the host
 * (commands/toolCaptures.ts) supplies the folders and lists.
 */
import * as path from "node:path";

/** The paths `text` may mean: a `file:` URI's path, an absolute path, else relative to each of `dirs`. */
export function captureCandidates(text: string, dirs: readonly string[]): string[] {
  let name = text.trim().replace(/^["'`]|["'`]$/g, "");
  if (/^file:\/\//i.test(name)) {
    try {
      name = decodeURIComponent(new URL(name).pathname);
      // (file:///C:/x on Windows: the pathname keeps a leading slash)
      if (/^\/[A-Za-z]:\//.test(name)) {
        name = name.slice(1);
      }
    } catch {
      return [];
    }
  }
  if (!name) {
    return [];
  }
  return path.isAbsolute(name)
    ? [path.normalize(name)]
    : [...new Set(dirs.map((d) => path.join(d, name)))];
}

const same = (a: string, b: string): boolean =>
  process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;

/** Whether `file` is inside one of `roots` (or is one). */
export function insideAny(file: string, roots: readonly string[]): boolean {
  return roots.some((root) => {
    const rel = path.relative(root, file);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  });
}

/** The paths of `known` whose file name is `name`'s (without duplicates). */
export function byFileName(name: string, known: readonly string[]): string[] {
  const base = path.basename(name.trim());
  return [...new Set(known.filter((p) => same(path.basename(p), base)))];
}

/** Whether the tools may read `file`: open in the viewer, in Recent Captures, or in a workspace folder. */
export function toolsMayRead(
  file: string,
  places: { open: readonly string[]; recent: readonly string[]; folders: readonly string[] },
): boolean {
  return (
    places.open.some((p) => same(p, file)) ||
    places.recent.some((p) => same(p, file)) ||
    insideAny(file, places.folders)
  );
}
