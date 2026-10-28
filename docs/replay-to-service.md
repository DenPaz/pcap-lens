# Replay to Service

Tracking document for the **Replay to Service** feature: replaying the
operator's side of a capture to a local service (an interception collector, a
SIP server…) over new connections, with the original timing. Not packaged
(`docs/**` is in `.vscodeignore`).

## Goal

Open a capture of operator → collector delivery traffic (lawful interception
HI2/HI3, or any client → server traffic) in PCAP Lens, pick where each
recorded server port should go (an IP and a port on this machine, typically a
microservice in Docker Desktop with host networking), and replay it: the
service receives the same data, in the same order, with the same pauses, as
if the operator were sending it now.

## Definitions

- **Operator side / client**: the end of a recorded TCP connection that opened
  it (sent the SYN), or, without a SYN in the capture, the end whose port is
  the higher one. For UDP, the sender of a flow's first datagram.
- **Recorded target**: a server end in the capture, `protocol + IP + port`
  (e.g. `tcp 10.20.0.5:11001`). One row of the replay form.
- **Mapping**: recorded target → replay IP and port (e.g. `10.20.0.5:11001` →
  `127.0.0.1:11001`). Every recorded target can have its own port.
- **HI2 / HI3**: the lawful interception handover interfaces for
  interception-related information (who, when, where) and for the content of
  communication; usually separate TCP connections on separate ports.
- **Collector**: the receiving system (the LEMF in ETSI terms); it listens,
  the operator's delivery function connects to it.
- **Scope**: which packets are replayed: every packet, or those matching a
  display filter (the viewer's current filter). Ignored packets (Ctrl+D) are
  left out, as in statistics and exports.
- **Speed**: real time (1×), faster (2×, 5×, 10×…), or as fast as possible
  (0: no waiting).

## Decisions

- **Content replay, not packet replay (tcpreplay)**: the collector is a TCP
  endpoint. Raw packets carry the recorded sequence numbers, so a live TCP
  stack resets the connection; they would also need address rewriting and
  admin rights, and on Docker Desktop for Mac they don't reliably reach
  containers. New connections with the recorded bytes need none of that and
  work on macOS, Windows and Linux. (Packet replay for passive probes is a
  possible later mode.)
- **Only the operator side is sent.** The collector's replies (keep-alive
  responses, acknowledgements) are read and counted, never waited on.
- **Timing**: each record is due at `(time - first time) / speed` after the
  start; connections open at their SYN (or first data) time; connections that
  overlapped in the recording overlap again.
- **TCP data is deduplicated by sequence number**: retransmissions are skipped,
  a partial overlap sends only the new bytes, a gap (data missing from the
  capture) is counted and the data after it is still sent.
- **A client FIN closes our sending side** (after its data); a client RST
  closes the connection.
- **Local targets only by default**: loopback, private and link-local
  addresses (names are resolved and every address is checked). Anything else
  needs `allowPublic` (an application-scoped setting in the UI phase).
- **No TLS in the first version**: encrypted delivery can't be replayed as
  is; a later version can replay decrypted content (key log) over a new TLS
  connection.
- **Stdlib only** (backend rule): sockets, selectors, no extra tools.
- **Test data is synthetic** (`test/fixtures/generate.py`): no real or
  internal interception captures and no internal dissector code in the
  repository.

## Backend API (phase 1)

- `replay_targets {filter?}`: the recorded targets of the packets in scope,
  in order of their first data.
  - Returns `{filter, targets, first, last, duration}`.
  - Each target: `key` (`"tcp 10.20.0.5:11001"`), `proto`, `ip`, `port`,
    `connections`, `packets`, `bytes`, `retransmissions`, `gaps`, `first`,
    `last`, `firstFrame`, `protocol`.
  - `protocol` is the packet list's Protocol column of the first data packet
    (HI2/HI3 with the internal Lua dissectors loaded).
  - Cached per scope; needs a completely indexed capture.
- `replay {filter?, targets, speed?, loops?, allowPublic?}`: replays until
  done, stopped or cancelled.
  - `targets` maps recorded target keys to `{ip, port}`; recorded targets
    left out are skipped.
  - `speed`: 1 = real time, 0 = no pauses (at most 1000); `loops`: 1–1000.
  - Progress notifications: `phase` `"replay"`, `fraction`, `loop`, `sent`,
    `received`, `open`, `targets` (each target's counts, as in the result)
    and `log` (new lines `{time, level, text, target?}`: connections
    opened, closed by the service, errors, loops).
  - Returns `{filter, stopped, seconds, loops, speed, targets, log}`; each
    target: `key`, `to`, `connections`, `opened`, `refused`, `reset`,
    `closedByPeer`, `packets`, `bytes`, `dropped`, `received`, `datagrams`,
    `errors`, `errorCount`; `log` holds the lines not reported yet.
- `replay_stop` → `{stopped}`: ends the running replay cleanly, including a
  tshark pass still looking for packets.

## The panel (phase 2)

_PCAP: Replay to Service…_ (☰ Capture, or the editor title's overflow menu)
opens one panel per capture:

- **Packets**: all, or the packets the viewer's filter shows.
- **Targets table**: one row per recorded target, with its protocol (as the
  packet list names it), connections, packets and bytes, and notes about
  retransmissions (sent once) and gaps (data missing from the capture).
  Each row has a checkbox, a destination IP and a port. A row starts with
  the destination used last for that recorded target, else `127.0.0.1` and
  the recorded port. _Same IP for All_ sets every row's IP.
- **Presets**: named mappings in the `pcapViewer.replay.presets` setting
  (user settings, editable in settings.json). Picking one fills the rows
  whose recorded target it names, or, for a capture recorded with another
  server address, the rows with the same protocol and port; the other rows
  are unchecked. _Save Preset…_ stores the checked rows.
- **Speed** (real time, 2×, 5×, 10×, 100×, no pauses) and **loops**.
- **Start / Stop**; while running: a progress bar, totals, each row's sent
  and received bytes and result (opened, refused, reset, errors), and a
  log. The summary says how long it took, what was sent, what wasn't
  delivered and how many errors there were.
- Public destinations are refused unless
  `pcapViewer.replay.allowPublicTargets` is on (application scope); the
  refusal links to the setting.

## Phases

### Phase 1: the replay engine

- [x] Tracking document
- [x] Fixture `replay.pcap` (two collector ports, overlapping connections,
      pauses, retransmission, partial overlap, collector replies, a connection
      without SYN, a UDP flow, unrelated traffic)
- [x] `replay.py`: records from the tshark pass, the planner, target checks,
      the socket engine
- [x] `service/replaying.py`: `replay_targets`, `replay`, `replay_stop`
- [x] Tests: planner units; targets; exact bytes into local TCP/UDP servers;
      mapping; replies; timing; refused ports; stop; scope; public targets
- [x] CLAUDE.md design entry; lint, types, full suite; pushed to `dev`

### Phase 2: the Replay panel

- [x] Command `pcapViewer.replay` (☰ Capture group, editor title overflow)
- [x] Panel: targets table with editable IP and port per row, "same IP for
      all", scope (all / current filter), speed, loops
- [x] Presets (saved mappings), `pcapViewer.replay.allowPublicTargets`
      (application scope)
- [x] Live progress per target, event log, Stop, summary
- [x] Panel e2e test with axe, smoke test of the command

### Phase 3: polish and release

- [x] Status bar indicator in the viewer while replaying
- [x] README section, CHANGELOG entry
- [ ] Release 0.25.0
- [ ] Check against a real collector in Docker with a real capture (by the
      user, on their machine)

## Later

- TLS delivery: decrypted content (key log) over a new TLS connection.
- Packet replay (tcpreplay in a helper container) for passive probes.
- Pick a running Docker container's published ports as targets.
