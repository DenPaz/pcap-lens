import * as vscode from "vscode";
import { readPanelPlacement } from "../config";
import type { PcapEditorSession } from "../pcapEditor";

/**
 * Where a capture's analysis panels open (pcapViewer.panelPlacement):
 * "beside" the capture, as editor tabs in the next column, or "below" it, in
 * an editor group under the capture's, so the capture keeps its width and the
 * panels share the lower group as tabs. VS Code has no column for "the group
 * below", so the first panel opens in the capture's own group and is moved
 * down (workbench.action.moveEditorToBelowGroup, which makes the group when
 * there is none); the next ones open in the group the last one went to, while
 * it is still open.
 */

/** Per capture: the group its last panel went to (below mode). */
const lower = new WeakMap<PcapEditorSession, vscode.ViewColumn>();

const groupOpen = (column: vscode.ViewColumn) =>
  vscode.window.tabGroups.all.some((g) => g.viewColumn === column);

/** The column a new panel of `session` opens in. */
export function panelColumn(session: PcapEditorSession): vscode.ViewColumn {
  if (readPanelPlacement(session.uri) !== "below") {
    return vscode.ViewColumn.Beside;
  }
  const column = lower.get(session);
  if (column !== undefined && column !== session.panel.viewColumn && groupOpen(column)) {
    return column;
  }
  return session.panel.viewColumn ?? vscode.ViewColumn.Active;
}

/**
 * After `createWebviewPanel(…, panelColumn(session), …)`: in below mode, move
 * a panel that opened in the capture's group under it, and remember where the
 * panel is (also when it is dragged elsewhere later) for the next ones.
 * Returns the listener to dispose with the panel.
 */
export function placePanel(
  panel: vscode.WebviewPanel,
  session: PcapEditorSession,
): vscode.Disposable {
  const remember = () => {
    const column = panel.viewColumn;
    if (
      readPanelPlacement(session.uri) === "below" &&
      column !== undefined &&
      column !== session.panel.viewColumn
    ) {
      lower.set(session, column);
    }
  };
  const listener = panel.onDidChangeViewState(remember);
  if (
    readPanelPlacement(session.uri) === "below" &&
    panel.viewColumn === session.panel.viewColumn
  ) {
    // (The new panel is the active editor: the command moves it.)
    void vscode.commands
      .executeCommand("workbench.action.moveEditorToBelowGroup")
      .then(remember, () => undefined);
  } else {
    remember();
  }
  return listener;
}
