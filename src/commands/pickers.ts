import * as vscode from "vscode";

/**
 * A single-choice QuickPick that opens on the current choice, so Enter keeps
 * it and the arrows start from it. `showQuickPick` always highlights the
 * first item (and ignores `picked` without canPickMany): pickers that said
 * "current" on another row took the first one on Enter.
 */
export async function pickKeepingCurrent<T extends vscode.QuickPickItem>(
  items: readonly T[],
  isCurrent: (item: T) => boolean,
  options: {
    title?: string;
    placeHolder?: string;
    matchOnDescription?: boolean;
    matchOnDetail?: boolean;
    ignoreFocusOut?: boolean;
  },
): Promise<T | undefined> {
  const quick = vscode.window.createQuickPick<T>();
  quick.title = options.title;
  quick.placeholder = options.placeHolder;
  quick.matchOnDescription = !!options.matchOnDescription;
  quick.matchOnDetail = !!options.matchOnDetail;
  quick.ignoreFocusOut = !!options.ignoreFocusOut;
  quick.items = items;
  const current = items.find((i) => i.kind !== vscode.QuickPickItemKind.Separator && isCurrent(i));
  if (current) {
    quick.activeItems = [current];
  }
  const chosen = await new Promise<T | undefined>((resolve) => {
    quick.onDidAccept(() => resolve(quick.selectedItems[0] ?? quick.activeItems[0]));
    quick.onDidHide(() => resolve(undefined));
    quick.show();
  });
  quick.dispose();
  return chosen;
}
