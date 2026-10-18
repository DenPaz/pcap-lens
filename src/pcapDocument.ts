/** A capture file's document: the packet comment edits not saved yet (see PcapDocument). */
import * as vscode from "vscode";
import type { CaptureLimits } from "./captureModel";

/** A change of a document's comment edits; `reload`: the file's comments changed too (saved). */
interface CommentEditsChange {
  reload: boolean;
}

/** What "PCAP: Start Capture…" asks of the new capture's editor (capture_start). */
export interface CaptureRequest {
  interfaces: string[];
  /** Friendly names of the interfaces (for messages). */
  labels: string[];
  filter: string;
  limits: CaptureLimits;
  promiscuous: boolean;
}

/**
 * A capture file. The only thing that can be edited is packet comments: the
 * document holds the edits not saved yet (frame → new comment, "" deletes),
 * and every editor on it shows them (each backend gets the whole set).
 */
export class PcapDocument implements vscode.CustomDocument {
  private edits = new Map<number, string>();
  private readonly changeEmitter = new vscode.EventEmitter<CommentEditsChange>();
  readonly onDidChangeEdits = this.changeEmitter.event;
  /** An unsaved capture (tempCaptures.ts): always dirty, discarded when closed. */
  readonly temporary: boolean;
  /** The live capture to start, until the first load starts it (reloads open the file). */
  captureRequest?: CaptureRequest;
  /** VS Code was told the document is dirty (unsaved captures only). */
  markedUnsaved = false;
  private readonly onDispose?: () => void;

  constructor(
    readonly uri: vscode.Uri,
    restored?: Map<number, string>,
    options: { temporary?: boolean; capture?: CaptureRequest; onDispose?: () => void } = {},
  ) {
    this.edits = new Map(restored ?? []);
    this.temporary = !!options.temporary;
    this.captureRequest = options.capture;
    this.onDispose = options.onDispose;
  }

  get editCount(): number {
    return this.edits.size;
  }

  /** The edit of `frame`, undefined if it has none. */
  editOf(frame: number): string | undefined {
    return this.edits.get(frame);
  }

  /** Apply `changes` (undefined: drop that frame's edit). */
  apply(changes: Map<number, string | undefined>): void {
    for (const [frame, text] of changes) {
      if (text === undefined) {
        this.edits.delete(frame);
      } else {
        this.edits.set(frame, text);
      }
    }
    this.changeEmitter.fire({ reload: false });
  }

  /** Drop every edit (saved or reverted). */
  clear(reload: boolean): void {
    this.edits.clear();
    this.changeEmitter.fire({ reload });
  }

  /** The edits as the backend's set_comments/save_comments take them. */
  editsParam(): Record<string, string | null> {
    return Object.fromEntries([...this.edits].map(([n, t]) => [String(n), t || null]));
  }

  dispose(): void {
    this.changeEmitter.dispose();
    this.onDispose?.();
  }
}
