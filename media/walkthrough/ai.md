# Ask Copilot (optional)

With GitHub Copilot signed in, or another language model an extension
provides (local ones too: **Choose Language Model…**), PCAP Lens can help
through VS Code's Language Model API. Each feature says what it sends, and
anything computed from your capture needs your permission first (user
settings only, so a workspace can't turn it on). Addresses and host names go
out as stand-ins such as `IP_PRIVATE_1` (`pcapViewer.ai.pseudonymizeAddresses`).

| Feature                                   | Sends                                             | Needs                    |
| ----------------------------------------- | ------------------------------------------------- | ------------------------ |
| ✨ in the filter bar, **Suggest Filter**  | your description, protocol and field names        | nothing more             |
| ✨ in **Start Capture**'s filter box      | your description, the interfaces' names           | nothing more             |
| **New Lua Dissector from Description**    | your description and the dissector template       | nothing more             |
| **Triage Capture**, `@pcap /triage`       | check counts and statistics, no payloads          | `allowCaptureStatistics` |
| **Summarize Capture**, `@pcap /summary`   | statistics (addresses, host names, counts)        | `allowCaptureStatistics` |
| **Ask Copilot** in Expert Info, TCP graph | expert entries or a stream's numbers, no payloads | `allowCaptureStatistics` |
| `@pcap` questions with tools              | counts and statistics for filters                 | `allowCaptureStatistics` |
| **Ask Copilot About This Packet**         | packet rows and dissection trees                  | `allowPacketData`        |

Turn it all off with `pcapViewer.ai.enabled: false`. The README's
_Security_ section lists every limit.
