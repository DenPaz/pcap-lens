# MCP Server

PCAP Lens includes a [Model Context Protocol](https://modelcontextprotocol.io)
server, so AI assistants outside Copilot (Claude Code, Claude Desktop,
Cursor, Windsurf, VS Code's agent mode…) can analyse your captures with
tshark. Its tools only read: they never change a capture, and the server
opens no network port (it talks over stdin and stdout).

## Setting it up

- **VS Code 1.101 or newer**: the server is offered to VS Code's agent mode
  by itself (`pcapViewer.mcp.enabled`), over your workspace folders.
- **Other assistants**: run **PCAP: Copy MCP Server Configuration…** and
  pick one:
  - **Claude Code**: a `claude mcp add pcap-lens --scope user …` command to
    run once in a terminal;
  - **Claude Desktop, Cursor and others**: an `mcpServers` entry for the
    app's MCP configuration file;
  - **VS Code**: a `servers` entry for `.vscode/mcp.json`.

The configuration runs Python on a copy of the backend in VS Code's storage,
which the extension keeps up to date, so it keeps working after updates. It
looks like this:

```json
{
  "mcpServers": {
    "pcap-lens": {
      "command": "python3",
      "args": [
        "-P",
        "-m",
        "pcap_backend.mcp",
        "--root",
        "/home/me/captures",
        "--stand-ins"
      ],
      "env": { "PYTHONPATH": "<VS Code storage>/mcp/backend" }
    }
  }
}
```

### Options

| Option                      | What it does                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `--root DIR`                | A folder whose captures the tools may read (repeatable; default: the current folder)       |
| `--allow-packet-data`       | Also offer packet contents: `list_packets`, `packet_details`, `follow_stream`, text values |
| `--allow-packet-bytes`      | With packet data: payload byte dumps in `packet_details` too                               |
| `--stand-ins`               | Replace IP and MAC addresses by stand-ins (`IP_PRIVATE_1`…) in every result                |
| `--options FILE`            | PCAP Lens's dissection options per folder (Lua, Decode As, preferences, profile)           |
| `--tshark PATH`             | tshark's path                                                                              |
| `--cache-dir`, `--no-cache` | Where saved indexes go, or don't save them                                                 |

In VS Code, `pcapViewer.mcp.allowPacketData` and
`pcapViewer.ai.pseudonymizeAddresses` set the packet data and stand-in
options of the configuration it gives. Captures are dissected as in the
viewer: your Lua dissectors, Decode As rules, preferences, Wireshark profile
and tshark's plugins. Decryption keys stay in VS Code's secret storage and
aren't passed to the server.

## Tools

| Tool                                              | What it gives                                                                                                        |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `list_captures`                                   | Capture files in the allowed folders, with sizes and times                                                           |
| `capture_info`                                    | Packets, first and last packet time, duration, size, link type, format                                               |
| `overview`                                        | The capture at a glance: totals, packets over time, top addresses, protocols, services, HTTP, DNS, TLS               |
| `triage`                                          | About 30 checks counted in one pass, each with a display filter, first and last packet and where to look next; scans |
| `count_packets`                                   | Packets matching a display filter, with the first packet numbers                                                     |
| `statistics`                                      | Protocol hierarchy, conversations, endpoints, expert information (with packets), I/O, HTTP, DNS, SIP…                |
| `sessions`                                        | HTTP requests, DNS queries or TLS servers with response times; `only_problems`                                       |
| `tcp_stream`                                      | One TCP connection's retransmissions, zero windows, windows and round-trip times                                     |
| `voip_calls`                                      | SIP, H.323, MGCP and IAX2 calls with quality (MOS), problems, release reasons, RTP streams, registrations            |
| `rtp_stream`                                      | One RTP or IAX2 voice stream: loss, jitter, each lost or late packet, RTCP, a timeline                               |
| `sequence_check`                                  | Missing, duplicated, late and restarted messages by a sequence field, per stream                                     |
| `export_objects`                                  | Files carried over HTTP, SMB, TFTP, IMF, DICOM and FTP-DATA (names, sizes, packets; never their contents)            |
| `credentials`                                     | Logins sent in clear text by protocol and packet (user names only with packet data)                                  |
| `field_values`                                    | The values a field takes, most frequent first (text fields only with packet data)                                    |
| `compare_captures`                                | What changed between two captures: rates, checks, protocols, flows, endpoints, expert messages, scans                |
| `search_fields`, `validate_filter`                | Display filter fields by name or description; check a filter                                                         |
| `plugins`                                         | The dissector plugins tshark loads                                                                                   |
| `list_packets`, `packet_details`, `follow_stream` | Packet rows, dissection trees and stream payloads: only with `--allow-packet-data`                                   |

Results also come as structured content with an output schema (MCP
2025-06-18 and later). The first call on a capture indexes it, which can
take a while for a big file; the index is saved, so later calls are fast.

## Example prompts

- _List the captures and triage the newest one._
- _In office-after.pcap, which DNS queries failed, and from which client?_
- _Compare office-before.pcap with office-after.pcap: what changed?_
- _Check the GTP tunnels in s1u.pcapng for missing sequence numbers._
- _How was the voice quality of the calls in sip-trunk.pcap?_

## Privacy

Without `--allow-packet-data` the tools return statistics, counts and
names, never packet contents: no payloads, no text field values, no DTMF
digits, no user names. When the assistant asks for contents anyway, the
server tells it the user chose not to share them. With `--stand-ins`,
addresses are replaced in every result and put back in the tools'
arguments. Capture contents are marked as untrusted data, never
instructions.
