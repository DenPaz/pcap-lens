# Changelog

All notable changes, newest first. Each entry links to the pull request (or
commit) that made it. The format follows
[Keep a Changelog](https://keepachangelog.com); versions are plain
`major.minor.patch`.

## Unreleased

### Added

- Compare two captures with AI: `@pcap /compare baseline.pcapng` or _PCAP:
  Compare Captures with AI…_ explains what changed (check rates, new and gone
  hosts, services and flows, protocol mix, expert messages) from statistics
  tshark computes for both; the MCP server has the same as `compare_captures`.
  [ae3cc3c]

### Changed

- The repository is now
  [github.com/DenPaz/pcap-lens](https://github.com/DenPaz/pcap-lens) (the old
  URL redirects). [3a7f0de]

### Fixed

- The MCP server's results name the capture they are about (an assistant
  comparing two captures by hand swapped their statistics), a capture can be
  named without its folder, and `statistics` takes other spellings of a kind
  ("Protocol Hierarchy", `phs`). [f7a5283]

[3a7f0de]: https://github.com/DenPaz/pcap-lens/commit/3a7f0de
[ae3cc3c]: https://github.com/DenPaz/pcap-lens/commit/ae3cc3c
[f7a5283]: https://github.com/DenPaz/pcap-lens/commit/f7a5283

## 0.23.0 — 2026-10-24

### Added

- PCAP Lens's MCP server lets AI assistants (Claude Code, Claude Desktop,
  Cursor, VS Code's agent mode) read capture files with tshark: counts,
  statistics, triage and, if allowed, packets. _PCAP: Copy MCP Server
  Configuration…_ sets it up. [408a8c7]
- The MCP server's `field_values` tool counts a field's values (DNS response
  codes, ICMP types…), and its triage says where to look next. [1967f9c]
- The MCP server's `packet_details` can expand only the protocols asked for,
  keeping the other layers to one line each. [38cf37d]

### Changed

- Triage also counts ICMP, DNS and HTTP requests without a response, in
  captures of up to 200,000 packets (read twice for that). [1967f9c]

### Fixed

- Address stand-ins left most of an IPv4-mapped IPv6 address readable
  (`::ffff:192.168.1.2` became `IP6_PUBLIC_1.168.1.2`); it now becomes
  `::ffff:IP_PRIVATE_1`, like the IPv4 address. [8848a61]

[408a8c7]: https://github.com/DenPaz/pcap-lens/commit/408a8c7
[1967f9c]: https://github.com/DenPaz/pcap-lens/commit/1967f9c
[38cf37d]: https://github.com/DenPaz/pcap-lens/commit/38cf37d
[8848a61]: https://github.com/DenPaz/pcap-lens/commit/8848a61

## 0.22.0 — 2026-10-24

### Added

- _PCAP: Choose Language Model…_ picks the model AI help uses: Copilot's, any
  other an extension provides, or a local one (`pcapViewer.ai.model`). A
  chosen model that is missing is never replaced by another. [b6e5da3]
- Addresses and host names are replaced by stand-ins such as `IP_PRIVATE_1`
  before anything goes to the language model, and put back in its answers
  (`pcapViewer.ai.pseudonymizeAddresses`, on). [6e2bb0b]
- ✨ in _Start Capture_'s filter box turns a description into capture filters
  that dumpcap compiles before you pick one. [668f418]
- _PCAP: New Lua Dissector from Description…_ writes a dissector from the
  template and your description; tshark loads it, and its errors go back to
  the model, before it is saved. [e528baa]
- `@pcap /triage` and _PCAP: Triage Capture with AI_: ranked findings from 30
  checks tshark counts, each with a filter and packet links; the capture
  report can add them as a Findings section. [daf8400]

[b6e5da3]: https://github.com/DenPaz/pcap-lens/commit/b6e5da3
[6e2bb0b]: https://github.com/DenPaz/pcap-lens/commit/6e2bb0b
[668f418]: https://github.com/DenPaz/pcap-lens/commit/668f418
[e528baa]: https://github.com/DenPaz/pcap-lens/commit/e528baa
[daf8400]: https://github.com/DenPaz/pcap-lens/commit/daf8400

## 0.21.2 — 2026-10-24

### Fixed

- _Keep Packets_ could freeze the extension when a list of packet ranges with
  double spaces didn't parse. [78d2e86]
- _Start Capture_ showed an internal error when your user may not run dumpcap
  (Debian and Ubuntu: not in the `wireshark` group yet); it now says how to
  allow it, also for capture helpers and Capture to Files. [96e0722]

[78d2e86]: https://github.com/DenPaz/pcap-lens/commit/78d2e86
[96e0722]: https://github.com/DenPaz/pcap-lens/commit/96e0722

## 0.21.1 — 2026-10-24

### Changed

- The extension's code ships as one bundled file, so it loads faster: the
  package went from 197 files to 122 and from 785 KB to 680 KB. [8c24d7e]

### Fixed

- The VS Code Marketplace version and installs badges on the extension's page
  showed "retired badge". [edd5b1e]

[8c24d7e]: https://github.com/DenPaz/pcap-lens/commit/8c24d7e
[edd5b1e]: https://github.com/DenPaz/pcap-lens/commit/edd5b1e

## 0.21.0 — 2026-10-23

### Added

- Right-click menus in the panels: statistics rows (_Apply as Filter ›_ and
  _Prepare as Filter ›_ combined with the capture's filter, _Go to Packet_,
  _Copy ›_), Export Objects and the VoIP calls and streams; Shift+F10 or the
  menu key opens the selected row's. [c32bf02] [43a2bb1]

### Changed

- The panels look like the viewer: icons on every button, rounder buttons and
  fields, VS Code-style section headings and table headers. [c32bf02]
  [43a2bb1]
- The packet list's header shows where to drag to resize a column, and the
  selected row and field have rounded corners. [21dbb84]

[c32bf02]: https://github.com/DenPaz/pcap-lens/commit/c32bf02
[43a2bb1]: https://github.com/DenPaz/pcap-lens/commit/43a2bb1
[21dbb84]: https://github.com/DenPaz/pcap-lens/commit/21dbb84

## 0.20.0 — 2026-10-23

### Added

- Context menus with submenus (_Apply as Filter ›_, _Prepare as Filter ›_,
  _Conversation Filter ›_, _Colorize Conversation ›_, _Follow ›_, _Copy ›_),
  icons, key bindings and keyboard use; entries that don't apply are left out,
  and _Follow ›_ lists the packet's own streams. [c2018f3]
- Actions in the editor's title bar: Start/Stop Capture, Find, Follow Stream,
  a Statistics menu and the coloring switch. [dedadc8]
- A toolbar under the filter (go to, first/previous/next/last, back/forward,
  mark, find, coloring) and `pcapViewer.listDensity` for the row height.
  [95f8023]

### Changed

- ☰ All commands: icons on the headings, recently used commands first, and
  the statistics split into Streams, Statistics, Network Statistics, Service
  Statistics and Telephony. [76ca42f]
- The filter bar is one rounded field with its buttons inside and a coloured
  validity edge; filter buttons are pills; the status bar's items have icons.
  [95f8023]

[c2018f3]: https://github.com/DenPaz/pcap-lens/commit/c2018f3
[dedadc8]: https://github.com/DenPaz/pcap-lens/commit/dedadc8
[95f8023]: https://github.com/DenPaz/pcap-lens/commit/95f8023
[76ca42f]: https://github.com/DenPaz/pcap-lens/commit/76ca42f

## 0.19.0 — 2026-10-23

### Added

- VoIP Calls lists H.323, MGCP and IAX2 calls next to SIP's, with their call
  flow, media (RTP, or IAX2's voice frames), timings, release causes, DTMF
  digits, quality and media problems; IAX2 voice can be analysed, played and
  saved like RTP. [eb909ad]

[eb909ad]: https://github.com/DenPaz/pcap-lens/commit/eb909ad

## 0.18.0 — 2026-10-21

### Added

- Remote and other capture helpers (Wireshark's extcap): _Start Capture_
  lists sshdump, ciscodump, androiddump, udpdump, randpkt… with each
  helper's options in a form. [ff18c62]
- _Capture to Files…_: a new file every so many MB, seconds or packets, ring
  buffers, stop after N files, pcapng or pcap; then open or merge the files.
  [ff18c62]
- Saved capture filters in _Start Capture_'s filter box, and a Wireshark
  profile's capture filters in _Import from Wireshark Profile_. [ff18c62]
- _Capture Report…_: properties, protocol hierarchy, top conversations and
  endpoints, expert information and the packet list as Markdown or HTML.
  [515b32b]

[ff18c62]: https://github.com/DenPaz/pcap-lens/commit/ff18c62
[515b32b]: https://github.com/DenPaz/pcap-lens/commit/515b32b

## 0.17.0 — 2026-10-21

### Added

- _Export PDUs to File…_: the PDUs one of tshark's export taps collects
  (transport payloads, SIP messages, IP packets…) from the displayed or all
  packets, as a new capture. [b9403be]
- _Show Packet in New Window_ (packet list menu) keeps a packet's details and
  bytes in a panel of their own, and _Show File Format_ shows the capture
  file's own headers, records and pcapng blocks over its bytes. [09312e5]

[b9403be]: https://github.com/DenPaz/pcap-lens/commit/b9403be
[09312e5]: https://github.com/DenPaz/pcap-lens/commit/09312e5

## 0.16.0 — 2026-10-20

### Added

- _Enabled Protocols…_: switch protocols and heuristic dissectors on or off
  per workspace folder, from what Wireshark has; _Disable Protocol_ in the
  packet details' menu. [4bdc8ef]
- _Decryption Keys…_: Wi-Fi (WEP, WPA passphrases and PSKs), TLS RSA private
  keys, SSH and WireGuard key logs, IPsec ESP and Kerberos keytabs, kept in
  secret storage; capture editing embeds SSH and WireGuard key logs too.
  [710d578]
- GeoIP: MaxMind databases give IP endpoints country, city and AS columns and
  a world map, and the `ip.geoip.*` fields work. [1d9e2b0]
- IPv4 and IPv6 statistics, UDP multicast streams, resolved addresses and SCTP
  associations. [d22494f]

[4bdc8ef]: https://github.com/DenPaz/pcap-lens/commit/4bdc8ef
[710d578]: https://github.com/DenPaz/pcap-lens/commit/710d578
[1d9e2b0]: https://github.com/DenPaz/pcap-lens/commit/1d9e2b0
[d22494f]: https://github.com/DenPaz/pcap-lens/commit/d22494f

## 0.15.0 — 2026-10-20

### Added

- I/O graphs with up to eight graphs: a display filter each, packets, bytes,
  bits or SUM/COUNT/MAX/MIN/AVG/LOAD of a field, lines or bars, log scale.
  [0e017cc]
- _Use Wireshark Profile…_ (tshark runs with its preferences, Decode As and
  filter macros) and _Import from Wireshark Profile…_ (its coloring rules,
  filter buttons, saved filters and columns). [acfb607]
- _Show Packet Bytes…_ for a field: decoded (Base64, compressed, hex,
  percent-encoding, quoted-printable, ROT13) and shown as text, hex dump,
  C/Rust array, YAML or an image; search and save. [fb31e4d]
- Credentials, _Export TLS Session Keys…_ and _Firewall ACL Rules…_, as in
  Wireshark's Tools menu. [08c490f]

[0e017cc]: https://github.com/DenPaz/pcap-lens/commit/0e017cc
[acfb607]: https://github.com/DenPaz/pcap-lens/commit/acfb607
[fb31e4d]: https://github.com/DenPaz/pcap-lens/commit/fb31e4d
[08c490f]: https://github.com/DenPaz/pcap-lens/commit/08c490f

## 0.14.1 — 2026-10-20

### Fixed

- Going to a packet or applying a filter from a panel (VoIP, statistics,
  follow stream…) no longer opens the capture a second time beside it and
  leaves the first tab empty. [7aed74b]

[7aed74b]: https://github.com/DenPaz/pcap-lens/commit/7aed74b

## 0.14.0 — 2026-10-19

### Added

- _Play Call_ plays both directions of a VoIP call together (caller left,
  callee right) over a waveform you can click to seek; _Save Call Audio…_
  saves it as a stereo WAV. [452b59a]
- VoIP audio in G.722, G.726-32 and L16 besides G.711, including dynamic
  payload types the SDP names. [452b59a]
- RTCP: what each RTP stream's receiver reported (loss, jitter, round trip).
  [452b59a]
- SIP Statistics (messages, response codes, request methods, setup times)
  and a Registrations table in the VoIP panel. [452b59a]
- _Ask Copilot…_ about a VoIP call: its SIP flow, timings, stream statistics
  and problems, never audio, message bodies or DTMF digits. [452b59a]

[452b59a]: https://github.com/DenPaz/pcap-lens/commit/452b59a

## 0.13.0 — 2026-10-19

### Added

- VoIP calls show how long each call rang and took to answer, who hung up,
  the final response and its `Reason` header. [5ebe171]
- An estimated MOS (ITU-T E-model) for each RTP stream and call, from packet
  loss, jitter and codec. [5ebe171]
- The DTMF digits of a call, sent as RFC 4733 events or SIP INFO, each
  linked to its packet. [5ebe171]
- Media problems per call: no RTP or one-way audio, a codec the SDP didn't
  agree on, an SSRC change, long silences. [5ebe171]
- _Save Call…_ writes one call's SIP, RTP and RTCP packets to a new capture.
  [5ebe171]

[5ebe171]: https://github.com/DenPaz/pcap-lens/commit/5ebe171

## 0.12.0 — 2026-10-19

### Added

- A display filter builder: find a field by name or description, pick a
  relation and a value seen in the capture, then apply it. [4c54893]
- When no packet matches a filter, the list says why (a field no packet has,
  a case-sensitive comparison) and offers what to try next. [4c54893]
- A PCAP Lens view in the activity bar lists recent captures with packet
  counts, sizes and when they were opened. [4c54893]

[4c54893]: https://github.com/DenPaz/pcap-lens/commit/4c54893

## 0.11.0 — 2026-10-19

### Added

- The status bar shows the selected field's name, filter field and size, as
  in Wireshark ("Time to Live (ip.ttl), 1 byte"). [7266035]
- An overview strip beside the packet list shows the whole view's colors,
  marks, comments and Find matches; click or drag it to scroll. [7266035]
- `?` (or _PCAP: Keyboard Shortcuts_) lists the viewer's keyboard shortcuts.
  [7266035]

### Fixed

- The packet details tree reports expanded nodes to screen readers on the
  tree item, where ARIA expects it. [7266035]

[7266035]: https://github.com/DenPaz/pcap-lens/commit/7266035

## 0.10.1 — 2026-10-19

### Added

- Find Packet looks for text in the packet list's columns or the packet
  details as well as the packet bytes (a match in the details selects its
  field), and finds by regular expression. [4389b78]

[4389b78]: https://github.com/DenPaz/pcap-lens/commit/4389b78

## 0.10.0 — 2026-10-19

### Added

- Follow Stream: search the stream (`Ctrl+F`, Enter / Shift+Enter, matches
  highlighted) and _Filter Out This Stream_, which hides the stream within
  the display filter already applied. [03478e0]
- Follow HTTP/2, QUIC and WebSocket streams, with a sub-stream picker for
  the streams of an HTTP/2 or QUIC connection. [8aae6f8]
- Follow Stream shows the data as UTF-8, UTF-16, ISO 8859-1, EBCDIC, C
  arrays or YAML as well as ASCII, hex dump and raw. [8aae6f8]

[03478e0]: https://github.com/DenPaz/pcap-lens/commit/03478e0
[8aae6f8]: https://github.com/DenPaz/pcap-lens/commit/8aae6f8

## 0.9.0 — 2026-10-19

### Added

- Two-pass details for small captures (up to 10,000 packets,
  `pcapViewer.twoPassDetail`): references to later packets appear too, so a
  request names and marks its response, as in Wireshark. [f6bbeb9]
- Compare Packets: two packets' details side by side, aligned field by
  field, with the fields that differ (or exist in only one) marked and an
  _Only differences_ switch. From the packet list's menu or the ☰ menu.
  [e42090b]

[f6bbeb9]: https://github.com/DenPaz/pcap-lens/commit/f6bbeb9
[e42090b]: https://github.com/DenPaz/pcap-lens/commit/e42090b

## 0.8.0 — 2026-10-18

### Added

- The status bar shows the capture's expert information at a glance: the
  most severe findings with their count ("3 warnings"), every severity in the
  tooltip, and a click opens Expert Information. [1e2af9f]
- Related packets: while a packet is selected, the list marks the packets it
  refers to (the request it answers, the segment it acknowledges, the
  segments it reassembles…), like Wireshark's related-packet indicators.
  [26e01b9]
- Conversation Filter and Colorize Conversation in the packet list's menu:
  filter on, or color, the packet's Ethernet, IPv4, IPv6, TCP or UDP
  conversation (ten colors, for this editor only); _Reset Colorization_
  clears them. [137b196]
- Ignore packets (`Ctrl+D`, the packet list's menu): ignored packets are
  dimmed in the list and left out of statistics, the expert counts and
  exports; _Unignore All Packets_ brings them back. [dce57fe]

[1e2af9f]: https://github.com/DenPaz/pcap-lens/commit/1e2af9f
[26e01b9]: https://github.com/DenPaz/pcap-lens/commit/26e01b9
[137b196]: https://github.com/DenPaz/pcap-lens/commit/137b196
[dce57fe]: https://github.com/DenPaz/pcap-lens/commit/dce57fe

## 0.7.0 — 2026-10-18

### Added

- **Open BER Records as Packets**: a file of BER records back to back (call
  detail records and similar), which tshark refuses, opens as one packet per
  record, decoded by the dissector you choose (generic BER, any of tshark's,
  or a Lua one). Offered when such a file fails to open. [9c1afc4]
- **Packet diagram**: the details pane's _Diagram_ view draws each protocol's
  header 32 bits a row, every field to the bit, linked to the tree and bytes.
  [188ddcf]

### Fixed

- A notice under the filter bar (such as unknown columns removed) no longer
  disappears when the filter box is emptied. [985f8b3]
- A live capture's size limit now stops at the first packet past it; a fast
  interface could overshoot it by several packets. [91e898e]

[9c1afc4]: https://github.com/DenPaz/pcap-lens/commit/9c1afc4
[188ddcf]: https://github.com/DenPaz/pcap-lens/commit/188ddcf
[985f8b3]: https://github.com/DenPaz/pcap-lens/commit/985f8b3
[91e898e]: https://github.com/DenPaz/pcap-lens/commit/91e898e

## 0.6.0 — 2026-10-18

### Added

- **Protocol preferences**: right-click a protocol in the packet details (or
  run _PCAP: Protocol Preferences…_) to see its tshark preferences with their
  descriptions and current values, and change them. Values are checked, the
  capture reloads, and ↺ goes back to Wireshark's value. [3049e5e]
- The dividers between the packet list, details and bytes can be moved with
  the keyboard: focus one (Tab) and use the arrow keys. [c446d3a]

### Changed

- Screen readers: the packet list is announced as a grid with column
  headers, sort order and row numbers, the flow graph's rows as a list that
  follows the selection, and the VoIP call flow's rows as buttons. [c446d3a]

[3049e5e]: https://github.com/DenPaz/pcap-lens/commit/3049e5e
[c446d3a]: https://github.com/DenPaz/pcap-lens/commit/c446d3a

## 0.5.0 — 2026-10-17

### Added

- _PCAP: Install Python…_: when no Python is found, installs Python 3.14 with
  [uv](https://docs.astral.sh/uv/) (no admin rights needed), or links to
  python.org and uv's installer. The setup message and walkthrough offer it.
  [8b9486a]

### Changed

- Python 3.12 or newer is enough (was 3.14), so the Python that comes with
  Ubuntu 24.04 or Debian 13 works. A Python installed with uv is found even
  when it isn't on `PATH`. [8b9486a]

[8b9486a]: https://github.com/DenPaz/pcap-lens/commit/8b9486a

## 0.4.1 — 2026-10-15

### Changed

- Renamed to **PCAP Lens**: the VS Code Marketplace refused "PCAP Viewer" as
  too close to another extension's name. The extension ID, commands and
  settings are unchanged, so nothing needs reconfiguring. [#42]

[#42]: https://github.com/DenPaz/pcap-lens/pull/42

## 0.4.0 — 2026-10-15

### Added

- Packet colors follow the theme: in dark themes Wireshark's light coloring
  rules become a tint with a stripe in the rule's color, in high contrast a
  stripe only. `pcapViewer.coloringStyle` picks full colors, tint or stripe
  instead. [#39]

### Changed

- The viewer and its panels use VS Code's own icons (Codicons) instead of
  text symbols. [#39]
- The viewer and its panels share one set of sizes and controls, so buttons,
  inputs and spacing match everywhere. [#40]
- Toolbar icons look like VS Code's own: no border until hovered, and a
  highlight while pressed or switched on. [#40]
- The packet details draw indent guides, like VS Code's trees. [#40]

### Fixed

- High-contrast themes: the selected packet, tree node, menu entry and table
  row were invisible; they are outlined now, as VS Code does. [#39]

[#39]: https://github.com/DenPaz/pcap-lens/pull/39
[#40]: https://github.com/DenPaz/pcap-lens/pull/40

## 0.3.0 — 2026-10-14

### Added

- The ☰ menu's groups fold: it opens as a short list of headings with their
  command counts; a click, `Enter` or `→` unfolds one, and typing still
  searches every command. Open groups are remembered. [#34]
- _PCAP: Lua Dissectors…_ (also the status bar's _Lua_ link): choose which of
  the configured Lua scripts each capture loads, remembered per file. [#34]
- _PCAP: Open File in PCAP Viewer…_ (also in the Explorer's right-click menu):
  open any file tshark reads, whatever its name or without an extension, or
  get told why it can't be read (for example several BER records back to
  back). [#34]
- The log says why each capture (re)loads and how long starting tshark, the
  first rows and the whole index took. [#35]
- _PCAP: Show TShark Plugins_ lists the Wireshark plugins tshark loads (yours
  first) and opens the folder a new dissector plugin goes into; the README
  explains how to install one. [#36]

### Fixed

- Opening a capture failed when tshark's first run took over 30 s (macOS
  checks Wireshark.app the first time it runs after an install or update).
  tshark now gets 2 minutes, the viewer says why it's waiting after 5 s, and
  a backend that never answered is stopped. [#35]

[#34]: https://github.com/DenPaz/pcap-lens/pull/34
[#35]: https://github.com/DenPaz/pcap-lens/pull/35
[#36]: https://github.com/DenPaz/pcap-lens/pull/36

## 0.2.0 — 2026-09-28

The first published release. It adds everything since 0.1.0 below.

### Added

**Opening big captures**

- The first packets show within about half a second while the rest is
  indexed. The finished index is saved, so reopening an unchanged capture is
  instant (`pcapViewer.indexCache.*`, _PCAP: Clear Index Cache_). [#18]
- Resumable indexing: a capture closed before it was fully indexed shows the
  saved packets at once on the next open, then continues. [#29]
- A progress bar for indexing, filters, coloring and exports, with the
  percentage and packet count in the status bar. [#29]
- Quick view of late packets: from packet 20,000 on, details show in about
  0.3 s by dissecting only the 300 packets before (`pcapViewer.quickDetail.*`).
  [#17]
- Streaming filters: matches show as tshark finds them; ■ stops and keeps them.
  Finished results are saved with the index. [#19]
- Colors come with the packets: the coloring rules run in the index pass
  (about 6% slower) instead of a second full pass. [#20]

**Packet list and navigation**

- More file types open by default: gzip/zstd/lz4-compressed pcap(ng), `.ntar`,
  `tcpdump -C` pieces, snoop, ERF, PacketLogger, btsnoop; generic extensions
  via _Reopen Editor With…_. [#10]
- Find Packet (display filter, string, hex), frame links with back/forward
  history, conversation stepping, first/last packet, marks, time display
  formats and a time reference. [#12]
- Column customisation (Apply as Column, hide, rename, reorder), cell filters
  and bytes-pane copy formats. [#12]
- Multi-select (Shift/Ctrl+click, Shift+arrows, Ctrl+A) with mark, copy and
  export of the selection. [#13]
- Addresses sort numerically; the Time column sorts by the format shown. [#13]
- Packet comments: shown on rows and above the details; edit, undo and save
  them into the pcapng. [#23]
- Name resolution for MAC addresses, IP addresses and ports
  (`pcapViewer.nameResolution.*`). [#22]
- The ☰ menu in the filter bar lists every command, greyed out with the reason
  when it can't run. [#31]
- Filter buttons under the filter bar (`pcapViewer.filterButtons`). [#32]

**Analysis**

- TLS decryption with an `SSLKEYLOGFILE` key log (`pcapViewer.tlsKeyLogFile`,
  _PCAP: Set TLS Key Log File…_). [#19]
- Coloring rules editor (_PCAP: Edit Coloring Rules_). [#21]
- Flow graph and TCP stream graphs (Stevens, throughput, RTT, window). [#23]
- VoIP calls: SIP calls with a call flow, RTP streams with loss and jitter,
  per-packet stream analysis, G.711 playback and WAV export. [#30]
- HTTP, DNS, packet length and service response time statistics. [#32]

**Capture, export and import**

- Live capture on one or more interfaces into a new unsaved capture. [#24]
- Capture editing: time shift, remove duplicates, keep a range, truncate,
  split, embed TLS keys. [#24]
- Export Packet Dissections (text, PDML, JSON). [#21]
- Merge captures, and an offer to merge a rotated capture's pieces. [#21]
- Export Objects (HTTP, SMB, TFTP, IMF, DICOM, FTP-DATA). [#22]
- Import from Hex Dump (text2pcap). [#32]

**AI (optional, through VS Code's Language Model API)**

- Display filter suggestions (✨, _PCAP: Suggest Display Filter…_, `@pcap`),
  validated by tshark; no packet data is sent. [#11]
- _Ask Copilot About This Packet…_ and `@pcap /explain`, after a one-time
  consent (`pcapViewer.ai.allowPacketData`). [#16]
- Capture summaries (`@pcap /summary`), anomaly explanations
  (`@pcap /anomaly`) and read-only `@pcap` tools, gated by
  `pcapViewer.ai.allowCaptureStatistics`. [#25]

**Setup and distribution**

- _Get Started_ walkthrough, _PCAP: Check Python and TShark_ and _PCAP: Open
  Sample Capture_. [#26]
- Icon, screenshots, Marketplace details and a release workflow. [#26]
- Remote windows (WSL, SSH, Dev Containers), captures not on disk (open a
  copy) and Restricted Mode. [#27]

### Changed

- "Since previous displayed packet" is the previous packet of the filter in
  capture order, whatever the sort. [#13]
- _Manage Coloring Rules_ became _Edit Coloring Rules_, an editor instead of
  the settings. [#21]
- Statistics always show addresses, so their row filters match. [#22]
- On narrow editors the filter bar's buttons wrap to a second line. [#31]
- CI tests with tshark on Linux, macOS and Windows [#19], on the Node 24
  versions of its actions [#21].

### Fixed

- Cancelling works when AppArmor refuses to let tshark be killed. [#14]
- tshark 4.6 output: byte tabs stay named "Frame"; statistics trees parse the
  4.4+ layout. [#14], [#32]
- Ctrl+A selected the page's text instead of the packets. [#14]
- The busy indicator kept spinning after a sort; a notice could be wiped by a
  late validation. [#16]
- The list stopped growing after scrolling to its end while indexing or
  filtering. [#20]
- A streaming filter race. [#22]
- Pipes leaked when cancelling tshark. [#28]
- Closing VS Code mid-index could save a truncated index as complete. [#29]
- A background tshark outlived the backend at shutdown. [#32]

[#10]: https://github.com/DenPaz/pcap-lens/pull/10
[#11]: https://github.com/DenPaz/pcap-lens/pull/11
[#12]: https://github.com/DenPaz/pcap-lens/pull/12
[#13]: https://github.com/DenPaz/pcap-lens/pull/13
[#14]: https://github.com/DenPaz/pcap-lens/pull/14
[#16]: https://github.com/DenPaz/pcap-lens/pull/16
[#17]: https://github.com/DenPaz/pcap-lens/pull/17
[#18]: https://github.com/DenPaz/pcap-lens/pull/18
[#19]: https://github.com/DenPaz/pcap-lens/pull/19
[#20]: https://github.com/DenPaz/pcap-lens/pull/20
[#21]: https://github.com/DenPaz/pcap-lens/pull/21
[#22]: https://github.com/DenPaz/pcap-lens/pull/22
[#23]: https://github.com/DenPaz/pcap-lens/pull/23
[#24]: https://github.com/DenPaz/pcap-lens/pull/24
[#25]: https://github.com/DenPaz/pcap-lens/pull/25
[#26]: https://github.com/DenPaz/pcap-lens/pull/26
[#27]: https://github.com/DenPaz/pcap-lens/pull/27
[#28]: https://github.com/DenPaz/pcap-lens/pull/28
[#29]: https://github.com/DenPaz/pcap-lens/pull/29
[#30]: https://github.com/DenPaz/pcap-lens/pull/30
[#31]: https://github.com/DenPaz/pcap-lens/pull/31
[#32]: https://github.com/DenPaz/pcap-lens/pull/32

## 0.1.0

The project brief, never published.

### Added

- Custom editor for `.pcap`/`.pcapng`/`.cap`, backed by tshark through a
  stdlib-only Python backend. [#1]
- Packet list for millions of packets: virtualized rows, backend paging and
  sorting, custom columns. [#1]
- Protocol tree and hex view with two-way highlighting, including reassembled
  data. [#1]
- Display filters with validation, autocomplete, history and saved filters.
  [#2]
- Follow TCP/UDP/TLS/HTTP stream; statistics panels (conversations, endpoints,
  protocol hierarchy, I/O graph, expert information, capture properties). [#3]
- Lua dissectors, Decode As rules and preference overrides, per workspace
  folder. [#4], [#5]
- Coloring rules and export (pcapng/pcap, CSV/JSON, packet bytes). [#6]
- tshark permission errors under AppArmor or Snap explain the fix. [#7]
- A Makefile for installs, updates, checks and packaging. [#9]

[#1]: https://github.com/DenPaz/pcap-lens/pull/1
[#2]: https://github.com/DenPaz/pcap-lens/pull/2
[#3]: https://github.com/DenPaz/pcap-lens/pull/3
[#4]: https://github.com/DenPaz/pcap-lens/pull/4
[#5]: https://github.com/DenPaz/pcap-lens/pull/5
[#6]: https://github.com/DenPaz/pcap-lens/pull/6
[#7]: https://github.com/DenPaz/pcap-lens/pull/7
[#9]: https://github.com/DenPaz/pcap-lens/pull/9
