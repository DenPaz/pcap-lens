# sharkd as an accelerator — design note

Status: proposal, nothing built (2026-11). Measurements on this repository's
Linux container: 4 CPUs, Wireshark 4.2.2 (Ubuntu's `wireshark-common`), a
synthetic 200,000-packet capture (`generate.py --large 200000`, 29 MB) and
tshark's default preferences (TCP analysis on).

## Why

Every request the backend answers today starts a tshark that reads the
capture from the start. Most are fine, but some are slow on big captures,
and the slowest is the one users hit most: the details of a late packet.

| Request                        | Today (one tshark run) | sharkd, after loading |
| ------------------------------ | ---------------------- | --------------------- |
| Load (once per capture)        | —                      | 4.7–5.2 s             |
| Details of packet 199,000      | 9.3 s                  | 0.001 s               |
| A page of 100 rows at 150,000  | (row store, < 1 ms)    | 0.003 s               |
| Display filter `tcp.port==443` | 9.7 s                  | 1.2–1.4 s, then 0 s   |
| TCP conversations              | 4.5 s                  | 1.0 s                 |
| Five reports in one request    | (≥ 5 s, shared pass)   | 1.7 s                 |
| Follow a TCP stream            | ≈ one pass (4–9 s)     | 1.3 s                 |
| Peak memory                    | tshark ≈ 225 MB / 1M   | 252–269 MB / 200k     |

Details of packet 1,000,000 take 18 s today; the quick view (`editcap` and a
300-packet window) hides most of it, but it is approximate and the exact
detail still costs a pass. Two-pass details (forward references such as
`http.response_in`) cost two passes, so they are limited to 10,000 packets.

## What sharkd is

`sharkd` ships with Wireshark: Wireshark's dissection engine behind a
JSON-RPC 2.0 interface, one request per line, as the backend speaks to the
host. It reads the capture once (`load`), keeps every frame's metadata and
the dissectors' per-packet state in memory, as Wireshark's GUI does, and then
re-dissects a single packet on request. `sharkd -` reads requests from stdin
and answers on stdout; that is the only mode we would use (never `-a`, a
socket: the Wireshark docs say not to expose it to untrusted users).

Requests checked on 4.2.2: `load`, `status`, `analyse` (protocols, first/last time),
`frames` (rows with `skip`/`limit`/`filter`, coloring `bg`/`fg` per row,
custom columns), `frame` (`proto`: the tree; `bytes`: base64 of each data
source), `check` (filter validation with tshark's message), `complete`
(field names), `tap` (several at once: `conv:*`, `endpt:*`, `expert`,
`phs`, `stats:*` stats_tree reports, `rtp-streams`, `voip-calls`,
`multicast`, `srt:*`, `rtd:*`, `seqa:*`, `nstat:*`…), `follow`, `iograph`,
`setcomment`, `setconf` (a preference), `download` (TLS secrets, export
objects, RTP), `dumpconf`, `bye`.

### Availability

- Debian and Ubuntu: `/usr/bin/sharkd` in `wireshark-common`, which `tshark`
  depends on: every Linux user with the distribution's tshark has it
  (checked here).
- macOS: Homebrew's `wireshark` formula lists `sharkd` among its binaries
  ([formulae.brew.sh](https://formulae.brew.sh/formula/wireshark)); MacPorts
  installs `/opt/local/bin/sharkd`. To confirm on macOS CI.
- Windows: Wireshark's developer wiki says the standard installer doesn't
  include `sharkd.exe` ([wiki](https://wiki.wireshark.org/Development/sharkd);
  adding it was discussed in
  [2022](https://lists.wireshark.org/archives/wireshark-dev/202201/msg00002.html)).
  To confirm on the Windows CI runner. Until then Windows keeps tshark only.

So sharkd can only ever be an **accelerator**: the backend finds it next to
tshark (`find_tool("sharkd", sibling_of=tshark)`), uses it when present and
healthy, and everything keeps working without it.

## How dissection settings reach it

sharkd takes no `-o`, `-d`, `-X`, `-N` or `--disable-protocol` options, only
`-C <profile>`. What the viewer sends to tshark on its command line
(`DissectionOptions.argv`) has to reach sharkd another way:

| Setting                                   | Way in                                                                                   |
| ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| Preferences, TLS key log, name resolution | `setconf` before `load` (checked: a name tshark doesn't know answers -4004)              |
| Decode As                                 | `decode_as_entries` in a private config folder (`setconf` refused a `uat:` value, -4005) |
| Enabled protocols, heuristics             | `disabled_protos`, `enabled_protos`, `heuristic_protos` in that folder                   |
| Decryption keys, GeoIP folders            | the UAT files (`80211_keys`, `esp_sa`, `rsa_keys`, `maxmind_db_paths`) in that folder    |
| Coloring rules                            | `colorfilters` in that folder (rows come colored)                                        |
| Wireshark profile                         | `-C <name>`, the folder under `profiles/<name>`                                          |
| Lua scripts                               | `WIRESHARK_PLUGIN_DIR`: numbered copies, as the field catalogue does                     |

The config folder is the one coloring passes already build
(`prepare_config_dir`: the user's personal files copied, ours written over
them), made with `mkdtemp` (mode 0700) and removed on close. A side benefit:
decryption keys would no longer be on a command line, where the process list
shows them (README says so today).

Every setting must be checked to take effect the same way as with tshark:
the parity tests below cover it.

## What would move, and what stays

Stays with tshark: the index pass and the row store (paging, sorting,
CSV/JSON, saved indexes: sharkd can't sort, and the row store answers pages
in under a millisecond already), exports (`-w`), editing (`editcap`), live
capture and following a growing file, the fields passes (overview, session
tables, sequence check, VoIP signalling: `frames` with custom columns could
replace them later).

Would move, in this order:

1. **Exact packet details** (`packet_detail`): `frame {proto, bytes}`.
   sharkd's tree gives each item's field name (`fn`), label (`l`), `[offset,
length]` (`h`), its data source by index (`ds`), generated (`g`) and
   expert severity (`s`), plus the bytes of every source. That replaces
   PDML and its byte-source guesswork (`pdml._matching_source`), and,
   since sharkd has read the whole capture, forward references come for
   free: no `-2`, no 10,000-packet limit, no quick view needed once loaded.
   Checked on `http.pcap`: 963 of PDML's 1,026 labels are identical; the
   rest are whole-capture knowledge (TCP "Conversation completeness:
   Complete" where `-c N` saw "Incomplete", `http.response_in`), unnamed
   items (`text` in sharkd, no name in PDML) and the displayed-frame delta.
2. **Follow stream** and the **reports** (`tap`): structured JSON, no
   text parsing (`stats.py` parsers stay for tshark). One converter per
   table to today's `Table` shape, each checked against the tshark result.
3. **Display filters** (`frames {filter}`): 7× faster, and sharkd keeps the
   result, so the next page is free. But see _Cancelling_.

### Cancelling

sharkd answers one request at a time and can't stop one midway: a filter
over a million packets (≈ 7 s) holds up every other request, and the only
way to stop it is to kill sharkd and load again (≈ 25 s). So:

- one sharkd per open capture, a lock around it, a queue in front;
- only requests that finish quickly go to it unconditionally (details,
  follow, reports: about a second per 200k packets); filters go to it only
  while nothing else waits, and a newer filter or a close kills it and falls
  back to tshark while it reloads in the background;
- a sharkd that crashes or answers garbage is dropped for that capture
  (logged), and tshark answers.

## Costs

- **Memory**: 252–269 MB at 200k packets with TCP analysis, about
  1.3 KB a packet, so ≈ 1.3 GB at a million; one per open capture (the
  backend is per editor panel). Hence a limit: `pcapViewer.sharkd.maxPackets`
  (say 2,000,000), and no sharkd for a capture above it.
- **CPU at open**: loading is a second full pass, in parallel with the index
  pass. Start it after "done" (no CPU fight while the user waits for the
  first rows), or right away for small captures.
- **Version drift**: the JSON-RPC interface changed before 4.0 (legacy
  requests); require 4.0 or later. tshark 4.6's sharkd needs the same probe
  (CI's macOS and Windows runners have 4.6).

## Plan

1. A `sharkd.py` client (stdlib: `subprocess`, one JSON line each way, a
   lock, kill through `procs`), a `Sharkd` per `_Open`, started after
   "done" below `maxPackets`, configured as above. A setting
   `pcapViewer.sharkd` (`auto`, `off`), and the log saying which engine
   answered each request.
2. Exact details through it, with a converter to today's tree model and a
   parity test over every fixture: the tree, field names, positions and
   byte sources against the PDML route (differences allowed only where
   sharkd knows more: listed and asserted). The quick view and two-pass
   detail stay for captures without sharkd.
3. Follow and the reports, each with its parity test; then filters, with the
   cancelling rules above.
4. Measure on the 1M benchmark (`test/perf/bench.py` grows a `--sharkd`
   switch) and in the real-capture harness (a step comparing both engines'
   details per capture: its dissectors are where differences hide).

Open questions to answer before step 1: sharkd on macOS CI (Homebrew 4.6)
and Windows CI (expected absent); whether `setconf` covers name resolution
(`nameres.*`) and the TLS key log; memory at 1M; behaviour with Lua scripts
and a profile; sharkd 4.6's answers to the same probe.
