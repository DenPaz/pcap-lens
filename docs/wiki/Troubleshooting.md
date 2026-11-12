# Troubleshooting

Start with **PCAP: Show Log**: it says why a capture (re)loaded, where the
time went, and what tshark reported. **PCAP: Check Python and TShark** says
which tools PCAP Lens found.

| Symptom                                               | Fix                                                                                                                                                        |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "No Python 3.12+ interpreter found"                   | **PCAP: Install Python…**, or set `pcapViewer.pythonPath`.                                                                                                 |
| "tshark was not found"                                | Install tshark (see [Installation and Setup](Installation-and-Setup)) or set `pcapViewer.tsharkPath`.                                                      |
| "You don't have permission to read the file"          | Ubuntu's AppArmor profile for tshark: add `owner @{HOME}/** rw,` to `/etc/apparmor.d/local/tshark`, then `sudo apparmor_parser -r /etc/apparmor.d/tshark`. |
| Stopping a filter is slow ("could not stop")          | Same file: add `signal (receive) peer=unconfined,` and `signal (receive) peer=vscode,`.                                                                    |
| The first open after installing Wireshark is slow     | macOS checks the app the first time tshark runs; later opens are fast.                                                                                     |
| A big capture opens slowly                            | That is tshark's speed. `"pcapViewer.prefs": { "tcp.analyze_sequence_numbers": false }` helps; reopening uses the saved index.                             |
| "isn't a capture file in a format TShark understands" | _Reopen Editor With…_ another editor, or check the file with `capinfos`. A file of BER records opens with **Open BER Records as Packets…**.                |
| A Lua dissector or plugin isn't applied               | **PCAP: Show Log**; **Reload Dissectors** shows Lua errors. tshark ignores Lua and personal plugins as root; plugins must match your Wireshark version.    |
| TLS stays encrypted                                   | The key log must hold the capture's sessions: set `SSLKEYLOGFILE` before capturing, then **Set TLS Key Log File…**.                                        |
| Live capture: no interfaces, or "permission denied"   | Give dumpcap permission (see [Capture, Edit and Export](Capture-Edit-and-Export#live-capture)).                                                            |
| The AI buttons don't appear                           | Install GitHub Copilot or another model provider; check `pcapViewer.ai.enabled` and **Choose Language Model…**.                                            |
| A chat tool says "Not allowed"                        | Turn on the setting it names (`pcapViewer.ai.allowCaptureStatistics` or `allowPacketData`).                                                                |
| The MCP server finds no captures                      | Its `--root` folders decide what it may read: run **Copy MCP Server Configuration…** again from a window with the right folders.                           |

Still stuck? Open an [issue](https://github.com/DenPaz/pcap-lens/issues/new/choose)
with your VS Code, PCAP Lens and `tshark --version` versions and the log.
