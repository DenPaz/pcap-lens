from __future__ import annotations

import importlib
import importlib.util
import os
import pkgutil
import shutil
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import service as service_package
from pcap_backend import tshark
from pcap_backend.cancellation import CancelToken
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HAVE_TSHARK = shutil.which("tshark") is not None

# tshark reads the personal configuration (preferences, Decode As, colors…) and
# loads personal plugins from the home folder, so a developer's own Wireshark
# setup (a Lua dissector on UDP/9999, say) would change what the tests see. The
# whole session runs with an empty home instead; tests that need a personal
# file create it there (or in their own tmp_path).
_ISOLATED_ENV = (
    "HOME",
    "APPDATA",
    "XDG_CONFIG_HOME",
    "WIRESHARK_CONFIG_DIR",
    "WIRESHARK_PLUGIN_DIR",
)
_saved_env: dict[str, str | None] = {}
_isolated_home: tempfile.TemporaryDirectory[str] | None = None


def pytest_configure(config: pytest.Config) -> None:  # noqa: ARG001 - pytest's hook signature
    global _isolated_home  # noqa: PLW0603 - one home per session
    _isolated_home = tempfile.TemporaryDirectory(prefix="pcapviewer-home-")
    home = _isolated_home.name
    for name in _ISOLATED_ENV:
        _saved_env[name] = os.environ.pop(name, None)
    os.environ["HOME"] = home
    os.environ["APPDATA"] = home  # Windows: %APPDATA%\Wireshark
    os.environ["XDG_CONFIG_HOME"] = str(Path(home) / ".config")


def pytest_unconfigure(config: pytest.Config) -> None:  # noqa: ARG001 - pytest's hook signature
    for name, value in _saved_env.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    if _isolated_home is not None:
        _isolated_home.cleanup()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if HAVE_TSHARK:
        return
    skip = pytest.mark.skip(reason="tshark is not installed")
    for item in items:
        if "tshark" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def ctx() -> RequestContext:
    return RequestContext()


@pytest.fixture
def service():  # type: ignore[no-untyped-def]
    svc = PcapService()
    yield svc
    svc.shutdown()


@pytest.fixture
def opened(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "http.pcap")}, ctx)
    return service


SERVICE_MODULES = [
    importlib.import_module(f"pcap_backend.service.{m.name}")
    for m in pkgutil.iter_modules(service_package.__path__)
]


@pytest.fixture
def patch_service(monkeypatch: pytest.MonkeyPatch) -> Callable[[str, object], None]:
    """Sets a module-level name the service uses (a limit such as ``FIRST_BATCH``,
    or a tshark helper such as ``stream_lines``) in every
    ``pcap_backend.service`` module that has it: the service is split over
    those modules, each importing the names it needs."""

    def patch(name: str, value: object) -> None:
        modules = [m for m in SERVICE_MODULES if name in vars(m)]
        assert modules, f"no pcap_backend.service module uses {name}"
        for module in modules:
            monkeypatch.setattr(module, name, value)

    return patch


@pytest.fixture
def slow_index(patch_service: Callable[[str, object], None]) -> Iterator[threading.Event]:
    """The index pass shows its first rows after 3 packets, takes 0.1 s per
    packet up to the 8th, then holds the rest until ``release`` is set (at most
    20 s; then it goes at full speed). The hold keeps a slow machine from
    finishing the pass while a test still expects it to run. Cancelling the
    pass (closing the capture) ends a wait at once."""
    release = threading.Event()
    real = tshark.stream_lines

    def slow(
        argv: list[str], result: Any, token: CancelToken | None = None, **kwargs: Any
    ) -> Iterator[bytes]:
        index_pass = "-T" in argv and "_ws.col.info" in argv
        for i, line in enumerate(real(argv, result, token, **kwargs)):
            if index_pass and 3 <= i <= 8:
                end = time.monotonic() + (0.1 if i < 8 else 20)
                while not release.is_set() and time.monotonic() < end:
                    if token is not None and token.cancelled:
                        break
                    release.wait(0.02)
            yield line

    patch_service("stream_lines", slow)
    patch_service("FIRST_BATCH", 3)
    patch_service("FIRST_BATCH_S", 60.0)
    yield release
    release.set()


@pytest.fixture
def slow_filter(patch_service: Callable[[str, object], None]) -> Iterator[threading.Event]:
    """Filter passes (``-Y``) stream their first 2 matches at once, then take
    0.1 s per match until ``release`` is set; a streaming filter's first batch
    is 2 matches."""
    release = threading.Event()
    real = tshark.stream_lines

    def slow(argv: list[str], *args: Any, **kwargs: Any) -> Iterator[bytes]:
        filter_pass = "-Y" in argv
        for i, line in enumerate(real(argv, *args, **kwargs)):
            if filter_pass and i >= 2 and not release.is_set():
                release.wait(0.1)
            yield line

    patch_service("stream_lines", slow)
    patch_service("FIRST_BATCH", 2)
    patch_service("FIRST_BATCH_S", 60.0)
    yield release
    release.set()


@pytest.fixture
def tls_keylog(tmp_path: Path) -> tuple[Path, Path]:
    """A TLS capture carrying HTTP and the key log file that decrypts it
    (generated: TLS randoms differ on every run)."""
    spec = importlib.util.spec_from_file_location("generate", FIXTURES / "generate.py")
    assert spec is not None and spec.loader is not None
    generate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generate)
    capture, keylog = tmp_path / "tls-decrypt.pcap", tmp_path / "tls-keys.log"
    try:
        generate.tls_keylog_capture(capture, keylog)
    except (AttributeError, NotImplementedError, ssl.SSLError) as exc:  # no TLS-PSK here
        pytest.skip(f"cannot generate a TLS-PSK session: {exc}")
    return capture, keylog
