// Type-checking support for the plain-JS webview (see tsconfig.webview.json).
declare function acquireVsCodeApi(): {
  postMessage(message: unknown): void;
  getState(): any; // eslint-disable-line @typescript-eslint/no-explicit-any
  setState(state: unknown): void;
};

// Shared by the viewer's modules (src/webview/viewer/).
type Column = { id: string; title: string; field: string; numeric?: boolean; custom?: boolean };
type Row = {
  number: number;
  cells: string[];
  color?: number;
  cid?: number;
  marked?: boolean;
  addresses?: string[];
  comment?: string;
  commentEdited?: boolean;
};
type ColorRule = { name: string; foreground: string; background: string };
