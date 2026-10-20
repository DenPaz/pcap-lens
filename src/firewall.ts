/**
 * Firewall ACL rules for a packet (pure), like Wireshark's Tools → Firewall
 * ACL Rules: from the packet's addresses and ports, one rule per kind (MAC
 * source, IP source, IP destination, destination port, source address and
 * destination port) for a firewall product, denying or allowing, inbound or
 * outbound. The rules are text to copy: nothing here runs them.
 */

/** What a rule can be made of: the packet's innermost Ethernet, IP and TCP/UDP fields. */
export interface PacketEndpoints {
  ethSrc?: string;
  /** IPv4 or IPv6. */
  ipSrc?: string;
  ipDst?: string;
  ipv6?: boolean;
  proto?: "tcp" | "udp";
  srcPort?: number;
  dstPort?: number;
}

interface TreeNode {
  name?: string;
  show?: string;
  children?: TreeNode[];
}

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-f:.]+$/i;

/** The packet's innermost endpoints, from its detail tree (packet_detail's). */
export function packetEndpoints(tree: readonly TreeNode[]): PacketEndpoints {
  const out: PacketEndpoints = {};
  const walk = (nodes: readonly TreeNode[]) => {
    for (const node of nodes) {
      const v = node.show ?? "";
      switch (node.name) {
        case "eth.src":
          if (MAC_RE.test(v)) {
            out.ethSrc = v.toLowerCase();
          }
          break;
        case "ip.src":
        case "ip.dst":
          if (IPV4_RE.test(v)) {
            out[node.name === "ip.src" ? "ipSrc" : "ipDst"] = v;
            out.ipv6 = false;
          }
          break;
        case "ipv6.src":
        case "ipv6.dst":
          if (IPV6_RE.test(v) && v.includes(":")) {
            out[node.name === "ipv6.src" ? "ipSrc" : "ipDst"] = v;
            out.ipv6 = true;
          }
          break;
        case "tcp.srcport":
        case "udp.srcport":
        case "tcp.dstport":
        case "udp.dstport": {
          const n = Number(v);
          if (Number.isInteger(n) && n >= 0 && n <= 65535) {
            out.proto = node.name.startsWith("tcp") ? "tcp" : "udp";
            out[node.name.endsWith("srcport") ? "srcPort" : "dstPort"] = n;
          }
          break;
        }
      }
      if (node.children) {
        walk(node.children);
      }
    }
  };
  walk(tree);
  return out;
}

export const FIREWALL_PRODUCTS = [
  { id: "iptables", label: "Netfilter (iptables)" },
  { id: "nftables", label: "Netfilter (nftables)" },
  { id: "ciscoStandard", label: "Cisco IOS (standard)" },
  { id: "ciscoExtended", label: "Cisco IOS (extended)" },
  { id: "ipfilter", label: "IP Filter (ipfilter)" },
  { id: "ipfw", label: "IPFirewall (ipfw)" },
  { id: "pf", label: "Packet Filter (pf)" },
  { id: "netsh", label: "Windows Firewall (netsh)" },
] as const;

export type FirewallProduct = (typeof FIREWALL_PRODUCTS)[number]["id"];

export interface FirewallRule {
  /** What it matches, e.g. "IPv4 source address". */
  kind: string;
  rule: string;
}

type Kind = "mac" | "src" | "dst" | "port" | "srcPort";

/**
 * The rules `product` can express for the packet (`deny` or allow,
 * `inbound` or outbound), in a fixed order; kinds the packet lacks the
 * fields for, or the product can't express, are left out.
 */
export function firewallRules(
  p: PacketEndpoints,
  product: FirewallProduct,
  options: { deny: boolean; inbound: boolean },
): FirewallRule[] {
  const v = p.ipv6 ? "IPv6" : "IPv4";
  const names: Record<Kind, string> = {
    mac: "MAC source address",
    src: `${v} source address`,
    dst: `${v} destination address`,
    port: `${(p.proto ?? "").toUpperCase()} destination port`,
    srcPort: `${v} source address and ${(p.proto ?? "").toUpperCase()} destination port`,
  };
  const has: Record<Kind, boolean> = {
    mac: !!p.ethSrc,
    src: !!p.ipSrc,
    dst: !!p.ipDst,
    port: !!p.proto && p.dstPort !== undefined,
    srcPort: !!p.ipSrc && !!p.proto && p.dstPort !== undefined,
  };
  const out: FirewallRule[] = [];
  for (const kind of ["mac", "src", "dst", "port", "srcPort"] as const) {
    const rule = has[kind] ? ruleFor(product, kind, p, options) : null;
    if (rule) {
      out.push({ kind: names[kind], rule });
    }
  }
  return out;
}

function ruleFor(
  product: FirewallProduct,
  kind: Kind,
  p: PacketEndpoints,
  { deny, inbound }: { deny: boolean; inbound: boolean },
): string | null {
  const mac = p.ethSrc ?? "";
  const src = p.ipSrc ?? "";
  const dst = p.ipDst ?? "";
  const proto = p.proto ?? "tcp";
  const port = String(p.dstPort ?? "");
  const host = (a: string) => `${a}/${p.ipv6 ? 128 : 32}`;
  switch (product) {
    case "iptables": {
      const cmd = p.ipv6 ? "ip6tables" : "iptables";
      const head = inbound
        ? `${cmd} --append INPUT --in-interface eth0`
        : `${cmd} --append OUTPUT --out-interface eth0`;
      const jump = `--jump ${deny ? "DROP" : "ACCEPT"}`;
      switch (kind) {
        case "mac":
          // (The mac module matches source addresses only, and only coming in.)
          return inbound
            ? `iptables --append INPUT --in-interface eth0 --mac-source ${mac} ${jump}`
            : null;
        case "src":
          return `${head} --source ${host(src)} ${jump}`;
        case "dst":
          return `${head} --destination ${host(dst)} ${jump}`;
        case "port":
          return `${head} --protocol ${proto} --destination-port ${port} ${jump}`;
        case "srcPort":
          return `${head} --protocol ${proto} --source ${host(src)} --destination-port ${port} ${jump}`;
      }
      break;
    }
    case "nftables": {
      const head = `nft add rule inet filter ${inbound ? "input" : "output"}`;
      const ip = p.ipv6 ? "ip6" : "ip";
      const verdict = deny ? "drop" : "accept";
      switch (kind) {
        case "mac":
          return `${head} ether saddr ${mac} ${verdict}`;
        case "src":
          return `${head} ${ip} saddr ${src} ${verdict}`;
        case "dst":
          return `${head} ${ip} daddr ${dst} ${verdict}`;
        case "port":
          return `${head} ${proto} dport ${port} ${verdict}`;
        case "srcPort":
          return `${head} ${ip} saddr ${src} ${proto} dport ${port} ${verdict}`;
      }
      break;
    }
    case "ciscoStandard":
      // Standard lists match IPv4 sources only.
      return kind === "src" && !p.ipv6
        ? `access-list 1 ${deny ? "deny" : "permit"} host ${src}`
        : null;
    case "ciscoExtended": {
      if (p.ipv6) {
        return null;
      }
      const action = deny ? "deny" : "permit";
      switch (kind) {
        case "src":
          return `access-list 101 ${action} ip host ${src} any`;
        case "dst":
          return `access-list 101 ${action} ip any host ${dst}`;
        case "port":
          return `access-list 101 ${action} ${proto} any any eq ${port}`;
        case "srcPort":
          return `access-list 101 ${action} ${proto} host ${src} any eq ${port}`;
        default:
          return null;
      }
    }
    case "ipfilter": {
      const head = `${deny ? "block" : "pass"} ${inbound ? "in" : "out"} on le0`;
      switch (kind) {
        case "src":
          return `${head} from ${src} to any`;
        case "dst":
          return `${head} from any to ${dst}`;
        case "port":
          return `${head} proto ${proto} from any to any port = ${port}`;
        case "srcPort":
          return `${head} proto ${proto} from ${src} to any port = ${port}`;
        default:
          return null;
      }
    }
    case "ipfw": {
      const action = deny ? "deny" : "allow";
      const dir = inbound ? "in" : "out";
      const ip = p.ipv6 ? "ip6" : "ip";
      switch (kind) {
        case "mac":
          return `add ${action} MAC any ${mac} ${dir}`;
        case "src":
          return `add ${action} ${ip} from ${src} to any ${dir}`;
        case "dst":
          return `add ${action} ${ip} from any to ${dst} ${dir}`;
        case "port":
          return `add ${action} ${proto} from any to any ${port} ${dir}`;
        case "srcPort":
          return `add ${action} ${proto} from ${src} to any ${port} ${dir}`;
      }
      break;
    }
    case "pf": {
      const head = `${deny ? "block" : "pass"} ${inbound ? "in" : "out"} on $ext_if`;
      switch (kind) {
        case "src":
          return `${head} from ${src} to any`;
        case "dst":
          return `${head} from any to ${dst}`;
        case "port":
          return `${head} proto ${proto} from any to any port ${port}`;
        case "srcPort":
          return `${head} proto ${proto} from ${src} to any port ${port}`;
        default:
          return null;
      }
    }
    case "netsh": {
      const head = `netsh advfirewall firewall add rule name="PCAP Lens" dir=${inbound ? "in" : "out"} action=${deny ? "block" : "allow"}`;
      const portKey = inbound ? "localport" : "remoteport";
      switch (kind) {
        case "src":
          return `${head} remoteip=${src}`;
        case "dst":
          return inbound ? null : `${head} remoteip=${dst}`;
        case "port":
          return `${head} protocol=${proto.toUpperCase()} ${portKey}=${port}`;
        case "srcPort":
          return `${head} protocol=${proto.toUpperCase()} remoteip=${src} ${portKey}=${port}`;
        default:
          return null;
      }
    }
  }
  return null;
}
