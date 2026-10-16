# Python 3.12 or newer

PCAP Lens runs a small backend written in Python (standard library only:
nothing to `pip install`). It needs **Python 3.12 or newer** and looks for
`python3.14`, `python3.13`, `python3.12`, then `python3` and `python` (on
Windows: `py -3.14` … `py -3`, `python`), and finally for a Python installed
with [uv](https://docs.astral.sh/uv/), even when it isn't on `PATH`.

## The quick way

Click **Install Python**: with uv installed, it runs `uv python install 3.14`
in a terminal (no admin rights needed) and checks again when it's done.
Without uv, it links to python.org and to uv's installation page.

## Windows

- Install it from [python.org](https://www.python.org/downloads/) (the
  installer adds the `py` launcher), or run
  `winget install Python.Python.3.14`.

## macOS

- `brew install python@3.14`, or the installer from
  [python.org](https://www.python.org/downloads/).

## Linux

- Ubuntu 24.04 (3.12) and Debian 13 (3.13) already have it as `python3`.
- Fedora: `sudo dnf install python3.14`
- Any distribution: `uv python install 3.14`.

## In a remote window

In WSL, over SSH, in a Dev Container or a Codespace, PCAP Lens runs on the
remote machine: install Python **there** (the instructions above for its
system), not on your own computer. **Install Python** does that for you when
uv is installed there. Set the path in **Remote** settings (_Preferences:
Open Remote Settings_): local user settings don't apply there.

## Installed somewhere else?

Set **PCAP Lens › Python Path** (`pcapViewer.pythonPath`) to the
interpreter, for example `C:\Python314\python.exe` or
`/opt/python3.14/bin/python3`. Then click **Check Again**.
