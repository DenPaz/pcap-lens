import * as vscode from "vscode";
import {
  FIREWALL_PRODUCTS,
  type FirewallProduct,
  type FirewallRule,
  firewallRules,
  packetEndpoints,
} from "../firewall";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { requireSession } from "./filter";

const LAST_PRODUCT = "pcapViewer.firewallProduct";

type RuleItem = vscode.QuickPickItem & { rule?: string; all?: boolean };

/**
 * _PCAP: Firewall ACL Rules…_ (Wireshark's Tools menu): rules matching the
 * selected packet for a firewall product, denying or allowing, inbound or
 * outbound (the title bar's buttons switch); picking one copies it. `{frame,
 * product, deny, inbound}` skip the questions and return the rules (smoke test).
 */
export async function showFirewallRules(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  args?: { frame?: number; product?: FirewallProduct; deny?: boolean; inbound?: boolean },
): Promise<FirewallRule[] | undefined> {
  const session = requireSession(provider);
  const backend = session?.backend;
  if (!session || !backend?.running) {
    return undefined;
  }
  const frame = args?.frame ?? session.selectedFrame;
  if (frame === null) {
    void vscode.window.showInformationMessage("Select a packet to make firewall rules for.");
    return undefined;
  }
  let endpoints;
  try {
    const detail = await backend.request<{ tree: unknown[] }>(
      "packet_detail",
      { number: frame },
      { timeoutMs: 0 },
    );
    endpoints = packetEndpoints(detail.tree as Parameters<typeof packetEndpoints>[0]);
  } catch (err) {
    void vscode.window.showErrorMessage(`PCAP Lens: ${describeError(err)}`);
    return undefined;
  }
  let deny = args?.deny ?? true;
  let inbound = args?.inbound ?? true;
  if (args?.product) {
    return firewallRules(endpoints, args.product, { deny, inbound });
  }
  const last = context.globalState.get<string>(LAST_PRODUCT);
  const picked = await vscode.window.showQuickPick(
    FIREWALL_PRODUCTS.map((p) => ({
      label: p.label,
      description: p.id === last ? "last used" : "",
      id: p.id,
    })),
    { title: `Firewall ACL Rules for Packet ${frame}`, placeHolder: "Firewall product" },
  );
  if (!picked) {
    return undefined;
  }
  const product = picked.id;
  await context.globalState.update(LAST_PRODUCT, product);

  const qp = vscode.window.createQuickPick<RuleItem>();
  const toggleAction = (): vscode.QuickInputButton => ({
    iconPath: new vscode.ThemeIcon(deny ? "circle-slash" : "pass"),
    tooltip: deny ? "Denying: switch to allowing" : "Allowing: switch to denying",
  });
  const toggleDirection = (): vscode.QuickInputButton => ({
    iconPath: new vscode.ThemeIcon(inbound ? "arrow-down" : "arrow-up"),
    tooltip: inbound ? "Inbound: switch to outbound" : "Outbound: switch to inbound",
  });
  let rules: FirewallRule[] = [];
  const render = () => {
    rules = firewallRules(endpoints, product, { deny, inbound });
    qp.title = `${picked.label} · packet ${frame} · ${deny ? "deny" : "allow"} ${inbound ? "inbound" : "outbound"}`;
    qp.buttons = [toggleAction(), toggleDirection()];
    qp.items = rules.length
      ? [
          ...rules.map((r) => ({ label: r.kind, detail: r.rule, rule: r.rule })),
          { label: "", kind: vscode.QuickPickItemKind.Separator },
          { label: "$(copy) Copy All Rules", all: true },
        ]
      : [{ label: `${picked.label} has no rule for this packet's addresses and ports` }];
  };
  qp.placeholder = "Choose a rule to copy it (the buttons switch deny/allow and inbound/outbound)";
  qp.matchOnDetail = true;
  render();
  return new Promise((resolve) => {
    qp.onDidTriggerButton((button) => {
      if (button.tooltip?.startsWith("Denying") || button.tooltip?.startsWith("Allowing")) {
        deny = !deny;
      } else {
        inbound = !inbound;
      }
      render();
    });
    qp.onDidAccept(async () => {
      const item = qp.selectedItems[0];
      const text = item?.all ? rules.map((r) => r.rule).join("\n") : item?.rule;
      if (text) {
        await vscode.env.clipboard.writeText(text);
        vscode.window.setStatusBarMessage(
          item?.all ? `Copied ${rules.length} firewall rules` : "Copied the firewall rule",
          3000,
        );
        qp.hide();
      }
    });
    qp.onDidHide(() => {
      qp.dispose();
      resolve(rules);
    });
    qp.show();
  });
}

export function registerFirewallCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pcapViewer.firewallRules",
      (args?: { frame?: number; product?: FirewallProduct; deny?: boolean; inbound?: boolean }) =>
        showFirewallRules(context, provider, args),
    ),
  );
}
