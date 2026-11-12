# Installation and Setup

## 1. Install the extension

Search for **PCAP Lens** in VS Code's Extensions view, or install it from
the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=denpaz.pcap-viewer)
or [Open VSX](https://open-vsx.org/extension/denpaz/pcap-viewer) (VSCodium,
Cursor and other editors). Every release also attaches a `.vsix` to
[GitHub releases](https://github.com/DenPaz/pcap-lens/releases): _Extensions
› … › Install from VSIX…_. It needs VS Code 1.90 or newer.

## 2. Install tshark

tshark comes with Wireshark. PCAP Lens supports tshark 4.x.

| System         | Command or download                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| Debian, Ubuntu | `sudo apt install tshark`                                                                                 |
| Fedora, RHEL   | `sudo dnf install wireshark-cli`                                                                          |
| macOS          | `brew install wireshark`, or the app from wireshark.org                                                   |
| Windows        | The installer from [wireshark.org](https://www.wireshark.org/download.html), or `choco install wireshark` |

PCAP Lens finds tshark on your `PATH` and in Wireshark's usual install
folders. If it doesn't, set **`pcapViewer.tsharkPath`** to the program.

## 3. Install Python 3.12 or newer

The backend is a Python package that uses only the standard library: there
is nothing to `pip install`. PCAP Lens looks for `python3.14`, `python3.13`,
`python3.12`, `python3` and `python` (on Windows the `py` launcher too),
then asks [uv](https://docs.astral.sh/uv/) for a Python 3.12+.

No suitable Python? Run **PCAP: Install Python…**: with uv installed it runs
`uv python install 3.14` for you; without uv it links python.org and uv's
install page. Or set **`pcapViewer.pythonPath`**.

## 4. Check it

Run **PCAP: Get Started** (the walkthrough) or **PCAP: Check Python and
TShark**. The walkthrough ticks off Python and tshark, then opens a sample
capture and walks you through filtering and analysing it.

## Before the tools are installed: the basic view

A `.pcap` or `.pcapng` (also `.gz`) opens even without Python or tshark.
PCAP Lens reads the file itself and shows the packet list and each packet's
link, IP, TCP/UDP, ICMP, ARP, DNS, HTTP and TLS headers with their bytes.
Display filters work on those headers' common fields
(`ip.addr == 10.0.0.0/8 && tcp.port in {80, 443}`), and so do Find Packet,
marks and the filter builder. A banner says what is missing; once tshark
and Python are set up, **Reload** opens the full viewer.

## Remote windows (WSL, SSH, Dev Containers, Codespaces)

Everything runs on the remote machine: install tshark and Python there,
not on your laptop. Live capture uses the remote machine's interfaces.

Captures that aren't files on disk (Live Share, files inside archives,
virtual file systems) open as an unsaved copy, without asking up to 256 MB
(`pcapViewer.virtualFiles.autoCopyMB`).

## Restricted Mode (untrusted workspaces)

In an untrusted workspace, `pythonPath`, `tsharkPath`, `luaScripts` and
`dissectorsFolder` come from your user settings only, so a repository can't
choose the programs or Lua code that run.

## Ubuntu and AppArmor

Recent Ubuntu releases confine `/usr/bin/tshark` with an AppArmor profile
that only lets it read `/tmp` and Wireshark's folders. If opening a capture
says _"You don't have permission to read the file"_, add these lines to
`/etc/apparmor.d/local/tshark` and reload the profile:

```
owner @{HOME}/** rw,
signal (receive) peer=unconfined,
signal (receive) peer=vscode,
```

```sh
sudo apparmor_parser -r /etc/apparmor.d/tshark
```

The signal lines let PCAP Lens stop a tshark it no longer needs (for
example when you cancel a filter). The Snap package of Wireshark has the
same kind of confinement: use your distribution's package instead.

## Settings

Everything is under **PCAP Lens** in the Settings editor; IDs start with
`pcapViewer.`. The ones you are most likely to change:

| Setting                                                | What it does                                            |
| ------------------------------------------------------ | ------------------------------------------------------- |
| `tsharkPath`, `pythonPath`                             | The tools to use (empty: found automatically)           |
| `luaScripts`, `dissectorsFolder`, `decodeAs`, `prefs`  | Dissection, per workspace folder                        |
| `enabledProtocols`, `heuristicDissectors`              | Protocols and heuristics switched on or off             |
| `tlsKeyLogFile`, `wiresharkProfile`                    | TLS key log; the Wireshark profile tshark uses          |
| `columns`, `columnLayout`, `timeFormat`, `listDensity` | The packet list                                         |
| `paneLayout`, `showBytesPane`, `panelPlacement`        | Where the details, bytes and report panels go           |
| `coloringRules`, `coloringStyle`                       | Coloring rules and how they are drawn                   |
| `savedFilters`, `filterButtons`                        | Named filters and one-click filter buttons              |
| `nameResolution.*`                                     | Which names to show; `external` allows DNS lookups      |
| `geoip.databaseFolders`                                | MaxMind databases for GeoIP                             |
| `indexCache.*`, `quickDetail.*`, `twoPassDetail`       | Saved indexes; detail of late packets in big files      |
| `capture.*`                                            | Capture limits, promiscuous mode, saved capture filters |
| `replay.*`                                             | Replay presets; public destinations                     |
| `ai.*`, `mcp.*`                                        | AI features and what they may send                      |
