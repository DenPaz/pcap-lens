# Dissection and Decryption

Everything here changes how tshark dissects packets. Most settings are per
workspace folder, so captures in different folders can use different
dissectors. A change reloads the captures it affects.

## Lua dissectors

- **PCAP: New Lua Dissector…** writes a dissector from a template (its
  short name, description, and the UDP or TCP port it decodes); **New Lua Dissector from Description…** asks AI to
  write one, checks it with tshark and saves it only when it loads.
- Put scripts in a folder (`pcapViewer.dissectorsFolder`, **PCAP: Open
  Dissectors Folder**) or list them (`pcapViewer.luaScripts`).
- **PCAP: Reload Dissectors** checks every script for Lua errors, then
  re-reads the open captures. **PCAP: Lua Dissectors…** (also the status
  bar) chooses which scripts a capture loads.
- Their fields work in filters, autocomplete, columns and statistics.
- tshark refuses Lua when run as root.

A sample dissector (`backend/dissectors/example.lua`, UDP port 9999) shows
the structure.

## Decode As, preferences, protocols

- **PCAP: Decode As…** dissects a port or other value as a given protocol
  (`pcapViewer.decodeAs`); **Manage Decode As Rules** lists them.
- **PCAP: Protocol Preferences…** (also a field's menu): every preference
  tshark has, with its current value and where it comes from (here,
  Wireshark, default). Changes go to `pcapViewer.prefs`.
- **PCAP: Enabled Protocols…** switches protocols and heuristic dissectors
  on or off; a field's menu has _Disable Protocol_.

## Wireshark profiles and plugins

- **PCAP: Use Wireshark Profile…** dissects with one of your Wireshark
  profiles (its preferences, Decode As, disabled protocols, filter macros).
- **PCAP: Import from Wireshark Profile…** copies a profile's coloring
  rules, filter buttons, saved filters, capture filters and columns into
  PCAP Lens's settings.
- **Wireshark plugins**: compiled dissectors installed for tshark work here
  too. **PCAP: Show TShark Plugins** lists what tshark loads and opens the
  folder to install yours in. Build plugins for your Wireshark version.

## Decryption

- **TLS**: set a key log (`SSLKEYLOGFILE`) with **PCAP: Set TLS Key Log
  File…** (`pcapViewer.tlsKeyLogFile`). The capture reloads when the file
  changes. **Export TLS Session Keys…** writes the keys a capture uses.
- **PCAP: Decryption Keys…** keeps other keys in VS Code's secret storage:
  Wi-Fi WEP, WPA passphrases and PSKs, TLS RSA private keys, SSH and
  WireGuard key logs, IPsec ESP security associations and Kerberos keytabs.
- **Embed Key Log in Capture…** stores keys inside a pcapng, so it decrypts
  in Wireshark too without the key file.

tshark receives the keys on its command line, so they are visible in the
system's process list while it runs.

## GeoIP

Point `pcapViewer.geoip.databaseFolders` at folders holding MaxMind
databases (GeoLite2 City, Country or ASN `.mmdb` files). The `ip.geoip.*`
fields then work in filters and columns, and Endpoints get country, city
and AS columns and a world map.
