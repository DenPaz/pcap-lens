# Replay to Service

**PCAP: Replay to…** sends what a capture's clients sent, with the recorded
timing, to services you run: a lawful-interception collector in Docker, a
SIP server, a test backend. It needs no administrator rights and works on
Linux, macOS and Windows.

## How it works

It replays **content, not packets**. Each recorded TCP connection becomes a
new connection from your machine carrying the bytes its client sent, once
and in order: retransmissions are skipped, overlaps trimmed, segments
captured out of order put back in order. Each UDP datagram is sent again.
The services' answers are read and counted, never waited on.

(Raw packet replay, as tcpreplay does, carries the recorded TCP sequence
numbers, which a live TCP stack resets; it also needs administrator rights
and doesn't reach containers in Docker Desktop.)

The **client** of a connection is the end that sent the SYN (without one in
the capture, the end with the higher port); for UDP, the first sender. Each
server end is a **recorded target**, such as `tcp 10.20.0.5:11001`.

## The panel

1. Open a capture and run **PCAP: Replay to…** (☰ › Capture, or the editor
   title's overflow menu).
2. The table lists the recorded targets with their connections, packets and
   bytes. Give each one a destination IP and port: by default `127.0.0.1`
   and the recorded port, or what you used last time. _Same IP for All_
   sets every row.
3. Choose the **packets** (all, or the viewer's filter), the **speed** (real
   time to 100×, or no pauses), **loops** or _Until stopped_, and optionally
   **jitter** and **UDP loss**.
4. **Start**. Each row shows what was sent and received and how it ended
   (opened, refused, reset, errors); a log lists connections, errors and
   loops. **Stop** ends it cleanly. While it runs the viewer's status bar
   shows it too.
5. **Save Results…** writes the summary, each target's counts and the log,
   as text or JSON.

**Presets** (`pcapViewer.replay.presets`) store a set of destinations by
name; a preset also applies to a capture recorded with another server
address, by protocol and port. **Setups** save everything (captures,
destinations, options) to a JSON file to share with a team.

### Several captures

**More captures…** adds captures or a whole folder. They play one after
another (each from its first packet) or merged by their recorded times; the
open capture can be left out or moved among them.

### Safety

Destinations must be this machine, a private network or a link-local
address, unless `pcapViewer.replay.allowPublicTargets` is on (a user
setting: a workspace can't turn it on). TLS can't be replayed to a live TLS
service: the recorded bytes are encrypted for the original session.

## From the command line

**Copy Command Line…** in the panel saves the setup and copies a command
that replays it without VS Code, for scripts, CI jobs and long runs. It
runs `pcap-lens-replay.py`, which comes with the extension and needs only
Python 3.12 or newer and tshark:

```sh
python3 pcap-lens-replay.py --list delivery.pcapng          # the recorded targets
python3 pcap-lens-replay.py delivery.pcapng --to 127.0.0.1  # each to its recorded port
python3 pcap-lens-replay.py a.pcap b.pcap --map 'tcp/*:11001=127.0.0.1:12001' --order merged
python3 pcap-lens-replay.py --setup lab.json --loops 0 --duration 3600 --results run.json
```

| Option                                                                 | What it does                                                                |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `--setup FILE`                                                         | A setup saved by the panel (captures, targets, options)                     |
| `--filter EXPR`                                                        | Only the packets matching a display filter                                  |
| `--list`                                                               | List the recorded targets and exit                                          |
| `--map PATTERN=DEST`                                                   | Send targets matching `[tcp\|udp/]host:port` (`*` for any) to `host[:port]` |
| `--to HOST`                                                            | Send every other target to HOST, on its recorded port                       |
| `--allow-public`                                                       | Allow destinations outside this machine and private networks                |
| `--speed`, `--loops`                                                   | 1 = real time, 0 = no pauses; loops 0 = until stopped                       |
| `--order sequence\|merged`                                             | Several captures: one after another, or by time                             |
| `--jitter MS`, `--loss PCT`                                            | Move each paced event by ±MS; drop PCT % of UDP datagrams                   |
| `--duration S`                                                         | Stop after S seconds of sending                                             |
| `--results FILE`, `--json`                                             | Write the results (text, or JSON for a `.json` name); JSON lines on stdout  |
| `--options`, `--lua`, `--decode-as`, `--pref`, `--profile`, `--tshark` | Dissect as the viewer does                                                  |

Ctrl+C stops cleanly. The exit status is 0 when everything was delivered, 1
when a connection was refused or reset or a service didn't read everything,
2 for a usage error, 3 when the captures can't be read, and 130 when stopped
before sending. `--help` lists everything.
