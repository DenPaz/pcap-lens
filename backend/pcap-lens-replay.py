"""PCAP Lens's Replay to… from the command line (see pcap_backend/replay_cli.py).

Run it with Python 3.12 or newer, from anywhere: ``python3 pcap-lens-replay.py
--help``. This file's folder holds the ``pcap_backend`` package, and Python
puts a script's folder first on ``sys.path``, so nothing needs installing.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 12):  # noqa: UP036 (an older Python can run this far, not further)
    sys.exit(f"pcap-lens-replay needs Python 3.12 or newer (this is {sys.version.split()[0]})")

from pcap_backend.replay_cli import main

raise SystemExit(main())
