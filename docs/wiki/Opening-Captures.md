# Opening Captures

## File types

tshark recognises a capture by its content, so the file name only decides
which editor VS Code offers.

- **Open directly** (double-click in the Explorer): `.pcap`, `.pcapng`,
  `.cap`, `.ntar`, compressed captures (`.gz`, `.zst`, `.lz4`), `tcpdump -C`
  pieces (`trace.pcap1`, `trace.pcap2`…), snoop, ERF, PacketLogger and
  btsnoop.
- **Through _Reopen Editor With…_**: `.log`, `.dmp`, `.trc`, `.ber` and
  `*.[0-9]`, which are often something else.
- **Anything else tshark reads**: **PCAP: Open File in PCAP Lens…** (also in
  the Explorer's context menu) checks the file with tshark and opens it,
  whatever its name.
- **BER records** (a file of ASN.1 values back to back, such as call detail
  records): **PCAP: Open BER Records as Packets…** turns each record into a
  packet decoded by the dissector you pick.

**PCAP: Open Sample Capture** opens a small capture to try things on.

## Big captures

The first open indexes the capture with one tshark pass. Rows appear within
half a second while the rest is read, and a progress bar shows how far it
got. Sorting, Find Packet and some statistics wait until the index is done;
streaming filters work at once.

The index is saved (`pcapViewer.indexCache.*`), so opening the same capture
again with the same settings is instant. An open that was interrupted
resumes: the rows already read show at once while tshark catches up.
**PCAP: Clear Index Cache** deletes the saved indexes.

Details of a packet near the end of a huge capture need tshark to read up
to it. Past `pcapViewer.quickDetail.after` packets (20,000 by default) PCAP
Lens first shows a **quick view** that dissects only the packets just
before it (about 0.3 s), then replaces it with the exact one.

## Rotated captures

Opening one piece of a rotated capture (`tcpdump -C`/`-W`, dumpcap ring
buffers, `editcap -c` splits) offers to merge all pieces into one capture.
**PCAP: Merge Captures…** merges any captures, in time order or one after
another.

## Captures that are still being written

**PCAP: Follow Growing File** reads a capture another program is still
writing (tcpdump `-w`, dumpcap, a collector) and adds packets as they
arrive. PCAP Lens also offers it when a capture you have open grows on
disk. **PCAP: Stop Following** stops it. Only uncompressed pcap and pcapng
files can be followed.

## Recent Captures

The **PCAP Lens** view in the activity bar lists the captures you opened,
with their packet count, size and age. Click one to open it; the context
menu reveals or copies the file, or removes it from the list.

## Unsaved captures

Live captures, edited captures, imported hex dumps and merges open as
unsaved captures: `Ctrl+S` asks where to save them. Close one without
saving to discard it.
