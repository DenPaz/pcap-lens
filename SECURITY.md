# Security policy

PCAP Lens reads untrusted input: capture files can come from anywhere, and
their contents reach a webview, a Python backend, tshark and, when you allow
it, a language model. Problems in how it handles that input are security
bugs.

## Supported versions

Only the latest release gets fixes. Update from the Extensions view.

## Reporting a vulnerability

Please report it privately through GitHub's
[Report a vulnerability](https://github.com/DenPaz/vsc_pcap_viewer/security/advisories/new)
form (the repository's _Security_ tab), not as a public issue. Include the
PCAP Lens, VS Code and tshark versions, and a capture or steps that show the
problem if you can.

You should get an answer within a week. Once a fix is released, the advisory
is published with credit to you, unless you'd rather not be named.

## In scope

- Script or HTML injection into the viewer or its panels from packet data,
  file names or tshark output.
- Running a program, a command or Lua that the user didn't configure, for
  example through a workspace setting in an untrusted folder, or through
  shell interpretation of arguments.
- Writing or deleting files outside what an export or save asked for.
- Sending packet data, statistics or addresses to a language model without
  the settings and consent described in the README's _Security_ section.

## Out of scope

- Bugs in tshark, dumpcap or Wireshark's dissectors: report them to the
  [Wireshark project](https://gitlab.com/wireshark/wireshark/-/issues)
  (security issues as described in its own policy).
- Lua dissectors and plugins you installed or configured yourself: they run
  with your permissions by design.
- What a language model answers once you have enabled sending data to it.
