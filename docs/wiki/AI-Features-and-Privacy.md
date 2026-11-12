# AI Features and Privacy

PCAP Lens's AI help is optional. It goes through VS Code's Language Model
API: GitHub Copilot by default, or any model you pick with **PCAP: Choose
Language Model…**, local ones included. A model you chose is never swapped
for another. `pcapViewer.ai.enabled: false` turns every AI feature off.

The model never reads the capture file. PCAP Lens computes everything with
tshark and sends the model only what the feature needs and you allowed.

## The PCAP Lens agent

In Copilot Chat, pick **PCAP Lens** in the agent picker (or stay in Agent
mode, where the _analyze-capture_ skill applies) and ask in plain words:

- _What's wrong with this capture?_
- _Why do DNS lookups fail?_
- _Is TCP stream 12 healthy?_
- _What changed compared with baseline.pcapng?_

It answers from tools that compute with tshark, names the packets and
display filters that show each finding, and can apply a filter or go to a
packet in the viewer after you confirm. Any agent can use the tools: type
`#pcapTriage`, `#pcapOverview`…

The tools read the capture open in the viewer, or one you attach
(`#file:trace.pcap`) or name, if it is in a workspace folder, open in the
viewer or in Recent Captures. Note that Copilot also sends an attached
file's own contents to the model, whatever PCAP Lens's settings say; naming
the file in words doesn't.

| Tool                                                          | What it gives                                                                                         | Needs                    |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------ |
| `pcap_triage`                                                 | 33 checks tshark counts (resets, retransmissions, unanswered requests, errors…), scans, expert counts | `allowCaptureStatistics` |
| `pcap_overview`                                               | Totals, busiest interval, top addresses, protocols, services, HTTP, DNS, TLS                          | `allowCaptureStatistics` |
| `pcap_count`, `pcap_stats`, `pcap_capture_info`               | Counts for a filter; conversations, endpoints, hierarchy, expert, I/O; properties                     | `allowCaptureStatistics` |
| `pcap_tcp_stream`, `pcap_compare`                             | One connection's health; changes against a baseline capture                                           | `allowCaptureStatistics` |
| `pcap_list_packets`, `pcap_sessions`, `pcap_packet_details`   | Packet rows (20), HTTP/DNS/TLS sessions (30), dissection trees (4, no bytes)                          | `allowPacketData`        |
| `pcap_field_search`, `pcap_apply_filter`, `pcap_go_to_packet` | Field names; acting on the viewer after you confirm                                                   | nothing                  |

## In the viewer

- **Filter suggestions**: ✨ in the filter bar turns a description into
  display filters, each checked by tshark before you see it. The same for
  capture filters (Start Capture) and Lua dissectors (**New Lua Dissector
  from Description…**).
- **PCAP: Summarize Capture with Copilot**, **PCAP: Triage Capture with
  AI** (ranked findings with filters and packets), **PCAP: Compare Captures
  with AI…** (against a baseline file, scans named as scans).
- **Ask Copilot About Selected Packets…** (row menu) and **Ask Copilot** in
  the Expert Information, TCP Stream Graph and VoIP panels.

These open Copilot Chat with the `@pcap` participant (`/summary`, `/triage`,
`/compare`, `/explain`, `/anomaly`), or write the answer to a Markdown editor
when chat isn't available. Set `pcapViewer.ai.askIn` to `agent` to have them
ask the PCAP Lens agent instead; VS Code's newer chat engine runs agents but
no chat participants.

## What is sent, and the settings

| Feature                                                        | What is sent                                                                                       | Needs                    |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------ |
| Filter, capture filter and Lua help                            | Your description, the current filter, protocol and field names                                     | `ai.enabled`             |
| Triage, summary, compare, `/anomaly`                           | Capture properties, counts, top conversations and endpoints, expert entries (capped)               | `allowCaptureStatistics` |
| Tools: count, stats, triage, overview, TCP stream, compare     | Filters and counts, statistics tables (25 rows), overview top 10s, a stream's health, a comparison | `allowCaptureStatistics` |
| Explain packets; tools: list packets, sessions, packet details | Up to 8 packets' rows and trees (tools: 20 rows, 30 sessions, 4 trees, no bytes)                   | `allowPacketData`        |
| Packet bytes in explanations                                   | Up to 256 bytes per packet                                                                         | `allowPacketBytes`       |

- `pcapViewer.ai.allowCaptureStatistics` and `allowPacketData` are off until
  you agree to a one-time prompt; `allowPacketBytes` is off unless you turn
  it on. They are user settings: a workspace can't turn them on.
- **Address stand-ins** (`pcapViewer.ai.pseudonymizeAddresses`, on by
  default): IP and MAC addresses and host names become stand-ins such as
  `IP_PRIVATE_1`, `IP_PUBLIC_2` or `HOST_3` in everything sent, and are put
  back in the answer. Packet bytes are never sent while it is on.
- Everything taken from a capture is marked as untrusted data in the
  prompts: packet text is data to analyse, never instructions.
