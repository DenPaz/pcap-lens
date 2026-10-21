# Changelog

All notable changes, newest first. Each entry links to the pull request (or
commit) that made it. The format follows
[Keep a Changelog](https://keepachangelog.com); versions are plain
`major.minor.patch`.

## Unreleased

## 0.17.0 — 2026-10-21

### Added

- _Export PDUs to File…_: the PDUs one of tshark's export taps collects
  (transport payloads, SIP messages, IP packets…) from the displayed or all
  packets, as a new capture. [b9403be]
- _Show Packet in New Window_ (packet list menu) keeps a packet's details and
  bytes in a panel of their own, and _Show File Format_ shows the capture
  file's own headers, records and pcapng blocks over its bytes. [09312e5]

[b9403be]: https://github.com/DenPaz/vsc_pcap_viewer/commit/b9403be
[09312e5]: https://github.com/DenPaz/vsc_pcap_viewer/commit/09312e5

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

[4bdc8ef]: https://github.com/DenPaz/vsc_pcap_viewer/commit/4bdc8ef
[710d578]: https://github.com/DenPaz/vsc_pcap_viewer/commit/710d578
[1d9e2b0]: https://github.com/DenPaz/vsc_pcap_viewer/commit/1d9e2b0
[d22494f]: https://github.com/DenPaz/vsc_pcap_viewer/commit/d22494f

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

[0e017cc]: https://github.com/DenPaz/vsc_pcap_viewer/commit/0e017cc
[acfb607]: https://github.com/DenPaz/vsc_pcap_viewer/commit/acfb607
[fb31e4d]: https://github.com/DenPaz/vsc_pcap_viewer/commit/fb31e4d
[08c490f]: https://github.com/DenPaz/vsc_pcap_viewer/commit/08c490f

## 0.14.1 — 2026-10-20

### Fixed

- Going to a packet or applying a filter from a panel (VoIP, statistics,
  follow stream…) no longer opens the capture a second time beside it and
  leaves the first tab empty. [7aed74b]

[7aed74b]: https://github.com/DenPaz/vsc_pcap_viewer/commit/7aed74b

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

[452b59a]: https://github.com/DenPaz/vsc_pcap_viewer/commit/452b59a

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

[5ebe171]: https://github.com/DenPaz/vsc_pcap_viewer/commit/5ebe171

## 0.12.0 — 2026-10-19

### Added

- A display filter builder: find a field by name or description, pick a
  relation and a value seen in the capture, then apply it. [4c54893]
- When no packet matches a filter, the list says why (a field no packet has,
  a case-sensitive comparison) and offers what to try next. [4c54893]
- A PCAP Lens view in the activity bar lists recent captures with packet
  counts, sizes and when they were opened. [4c54893]

[4c54893]: https://github.com/DenPaz/vsc_pcap_viewer/commit/4c54893

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

[7266035]: https://github.com/DenPaz/vsc_pcap_viewer/commit/7266035

## 0.10.1 — 2026-10-19

### Added

- Find Packet looks for text in the packet list's columns or the packet
  details as well as the packet bytes (a match in the details selects its
  field), and finds by regular expression. [4389b78]

[4389b78]: https://github.com/DenPaz/vsc_pcap_viewer/commit/4389b78

## 0.10.0 — 2026-10-19

### Added

- Follow Stream: search the stream (`Ctrl+F`, Enter / Shift+Enter, matches
  highlighted) and _Filter Out This Stream_, which hides the stream within
  the display filter already applied. [03478e0]
- Follow HTTP/2, QUIC and WebSocket streams, with a sub-stream picker for
  the streams of an HTTP/2 or QUIC connection. [8aae6f8]
- Follow Stream shows the data as UTF-8, UTF-16, ISO 8859-1, EBCDIC, C
  arrays or YAML as well as ASCII, hex dump and raw. [8aae6f8]

[03478e0]: https://github.com/DenPaz/vsc_pcap_viewer/commit/03478e0
[8aae6f8]: https://github.com/DenPaz/vsc_pcap_viewer/commit/8aae6f8

## 0.9.0 — 2026-10-19

### Added

- Two-pass details for small captures (up to 10,000 packets,
  `pcapViewer.twoPassDetail`): references to later packets appear too, so a
  request names and marks its response, as in Wireshark. [f6bbeb9]
- Compare Packets: two packets' details side by side, aligned field by
  field, with the fields that differ (or exist in only one) marked and an
  _Only differences_ switch. From the packet list's menu or the ☰ menu.
  [e42090b]

[f6bbeb9]: https://github.com/DenPaz/vsc_pcap_viewer/commit/f6bbeb9
[e42090b]: https://github.com/DenPaz/vsc_pcap_viewer/commit/e42090b

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

[1e2af9f]: https://github.com/DenPaz/vsc_pcap_viewer/commit/1e2af9f
[26e01b9]: https://github.com/DenPaz/vsc_pcap_viewer/commit/26e01b9
[137b196]: https://github.com/DenPaz/vsc_pcap_viewer/commit/137b196
[dce57fe]: https://github.com/DenPaz/vsc_pcap_viewer/commit/dce57fe

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

[9c1afc4]: https://github.com/DenPaz/vsc_pcap_viewer/commit/9c1afc4
[188ddcf]: https://github.com/DenPaz/vsc_pcap_viewer/commit/188ddcf
[985f8b3]: https://github.com/DenPaz/vsc_pcap_viewer/commit/985f8b3
[91e898e]: https://github.com/DenPaz/vsc_pcap_viewer/commit/91e898e

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

[3049e5e]: https://github.com/DenPaz/vsc_pcap_viewer/commit/3049e5e
[c446d3a]: https://github.com/DenPaz/vsc_pcap_viewer/commit/c446d3a

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

[8b9486a]: https://github.com/DenPaz/vsc_pcap_viewer/commit/8b9486a

## 0.4.1 — 2026-10-15

### Changed

- Renamed to **PCAP Lens**: the VS Code Marketplace refused "PCAP Viewer" as
  too close to another extension's name. The extension ID, commands and
  settings are unchanged, so nothing needs reconfiguring. [#42]

[#42]: https://github.com/DenPaz/vsc_pcap_viewer/pull/42

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

[#39]: https://github.com/DenPaz/vsc_pcap_viewer/pull/39
[#40]: https://github.com/DenPaz/vsc_pcap_viewer/pull/40

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

[#34]: https://github.com/DenPaz/vsc_pcap_viewer/pull/34
[#35]: https://github.com/DenPaz/vsc_pcap_viewer/pull/35
[#36]: https://github.com/DenPaz/vsc_pcap_viewer/pull/36

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

[#10]: https://github.com/DenPaz/vsc_pcap_viewer/pull/10
[#11]: https://github.com/DenPaz/vsc_pcap_viewer/pull/11
[#12]: https://github.com/DenPaz/vsc_pcap_viewer/pull/12
[#13]: https://github.com/DenPaz/vsc_pcap_viewer/pull/13
[#14]: https://github.com/DenPaz/vsc_pcap_viewer/pull/14
[#16]: https://github.com/DenPaz/vsc_pcap_viewer/pull/16
[#17]: https://github.com/DenPaz/vsc_pcap_viewer/pull/17
[#18]: https://github.com/DenPaz/vsc_pcap_viewer/pull/18
[#19]: https://github.com/DenPaz/vsc_pcap_viewer/pull/19
[#20]: https://github.com/DenPaz/vsc_pcap_viewer/pull/20
[#21]: https://github.com/DenPaz/vsc_pcap_viewer/pull/21
[#22]: https://github.com/DenPaz/vsc_pcap_viewer/pull/22
[#23]: https://github.com/DenPaz/vsc_pcap_viewer/pull/23
[#24]: https://github.com/DenPaz/vsc_pcap_viewer/pull/24
[#25]: https://github.com/DenPaz/vsc_pcap_viewer/pull/25
[#26]: https://github.com/DenPaz/vsc_pcap_viewer/pull/26
[#27]: https://github.com/DenPaz/vsc_pcap_viewer/pull/27
[#28]: https://github.com/DenPaz/vsc_pcap_viewer/pull/28
[#29]: https://github.com/DenPaz/vsc_pcap_viewer/pull/29
[#30]: https://github.com/DenPaz/vsc_pcap_viewer/pull/30
[#31]: https://github.com/DenPaz/vsc_pcap_viewer/pull/31
[#32]: https://github.com/DenPaz/vsc_pcap_viewer/pull/32

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

[#1]: https://github.com/DenPaz/vsc_pcap_viewer/pull/1
[#2]: https://github.com/DenPaz/vsc_pcap_viewer/pull/2
[#3]: https://github.com/DenPaz/vsc_pcap_viewer/pull/3
[#4]: https://github.com/DenPaz/vsc_pcap_viewer/pull/4
[#5]: https://github.com/DenPaz/vsc_pcap_viewer/pull/5
[#6]: https://github.com/DenPaz/vsc_pcap_viewer/pull/6
[#7]: https://github.com/DenPaz/vsc_pcap_viewer/pull/7
[#9]: https://github.com/DenPaz/vsc_pcap_viewer/pull/9
