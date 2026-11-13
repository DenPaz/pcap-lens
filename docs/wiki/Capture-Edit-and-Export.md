# Capture, Edit and Export

## Live capture

**PCAP: Start Capture…** asks for one or more interfaces and an optional
capture filter (BPF syntax, checked before you start; the bookmark button
picks a saved one, `pcapViewer.capture.savedFilters`). Packets appear in a
new, unsaved capture as they arrive; the status bar shows the time, packets
and bytes, and **Stop** ends it. Limits by packets, seconds or size are in
`pcapViewer.capture.*`. Save the capture with `Ctrl+S`.

Capturing runs Wireshark's `dumpcap`, which needs permission:

- **Linux** (Debian, Ubuntu): `sudo dpkg-reconfigure wireshark-common`
  (answer _Yes_), then `sudo usermod -aG wireshark $USER` and log in again.
  Elsewhere: `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)`.
- **macOS**: install ChmodBPF (in Wireshark's disk image, or
  `brew install --cask wireshark-chmodbpf`) and log in again.
- **Windows**: install [Npcap](https://npcap.com) (Wireshark's installer
  includes it).

**Extcap helpers** (SSH remote capture, Cisco, Android, UDP listener,
randpkt…) are the programs in Wireshark's extcap folders. Their interfaces
appear in the list; their options are asked in a form and remembered, except
passwords.

## Capture to Files

**PCAP: Capture to Files…** writes straight to files without a live view:
a new file every so many kilobytes, seconds or packets, a ring buffer of the
last N files, or stop after N files. When it ends it offers to open the
latest file, merge them all, or show them.

## Editing

The editing commands write a new, unsaved capture and leave the original as
it was:

- **Time Shift…**: move every packet's time by an offset, or so the first
  packet starts at a given date and time.
- **Remove Duplicate Packets…**: within a window of packets or seconds.
- **Keep Packets in a Range…**: by packet numbers or times.
- **Truncate Packets…**: cut each packet to a length.
- **Split Capture…**: every N packets or seconds.
- **Embed Key Log in Capture…**: put TLS, SSH or WireGuard keys inside the
  pcapng, so it decrypts anywhere.
- **Merge Captures…**, **Import from Hex Dump…** (a hex dump from an editor,
  the clipboard or a file, as Wireshark copies it or as `hexdump -C` prints
  it, or a hex stream such as _Copy as Hex Stream_ or `tshark -e data`
  writes, one packet per line; the layout is detected and offered first).

## Export

- **Export Specified Packets…**: all, displayed, selected or marked packets,
  as pcapng or pcap.
- **Export Packet List as CSV/JSON…**, **Export Packet Dissections…** (text,
  PDML or JSON, with or without bytes), **Export Packet Bytes…**.
- **Export Objects…** (files carried in the capture), **Export PDUs to
  File…** (one protocol's messages as a new capture), **Export TLS Session
  Keys…**.
- **Capture Report…**: properties, protocols, top conversations and
  endpoints, expert information and, if you like, the packets and AI
  findings, as Markdown or HTML.
- **Firewall ACL Rules…**: rules for the selected packet's addresses or
  ports, for iptables, nftables, Cisco IOS, pf, ipfw, IP Filter or Windows
  Firewall, copied to the clipboard.

Exports write to a temporary file and rename it when done, so a cancelled or
failed export never leaves a partial file.
