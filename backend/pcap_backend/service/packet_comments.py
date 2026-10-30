"""Packet comments: reading them, the host's unsaved edits, saving with editcap."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from pcap_backend import comments
from pcap_backend.export import atomic_output, check_destination, unwritable_error
from pcap_backend.follow import FollowFile
from pcap_backend.protocol import InvalidParamsError, RequestContext, param
from pcap_backend.tshark import ToolError, ToolNotFoundError, find_tool, run

from .base import ServiceBase
from .helpers import _frame_list
from .state import MAX_FILTER_ARG, MAX_PAGE, _Open


def _comment_edits(params: dict[str, Any], frames: int) -> dict[int, str | None]:
    raw = params.get("edits")
    if not isinstance(raw, dict):
        raise InvalidParamsError("edits must map frame numbers to comments")
    edits: dict[int, str | None] = {}
    for key, text in raw.items():
        try:
            n = int(key)
        except (TypeError, ValueError):
            raise InvalidParamsError(f"not a frame number: {key!r}") from None
        if not 1 <= n <= frames:
            raise InvalidParamsError(f"no frame {n} in this capture")
        if text is not None and not isinstance(text, str):
            raise InvalidParamsError(f"the comment of frame {n} must be text or null")
        edits[n] = text or None
    return edits


def _replace(tmp: Path, dest: Path) -> None:
    """Replace ``dest`` by ``tmp``; on Windows a tshark still reading ``dest``
    makes that fail for a moment, so retry briefly."""
    for attempt in range(10):
        try:
            tmp.replace(dest)
        except PermissionError:
            if attempt == 9:
                raise ToolError("the capture file is in use; try saving again") from None
            time.sleep(0.2)
        else:
            return


class CommentsMixin(ServiceBase):
    """Packet comments: reading them, the host's unsaved edits, saving with editcap."""

    def _load_comments(self, f: _Open) -> None:
        """Read the file's packet comments (pool thread); report them with a
        "comments" notification when there are any (rows fetched before don't
        show them)."""
        try:
            f.comments = comments.read_comments(f.path)
        except comments.UnreadableError as exc:
            f.comments_error = str(exc)
        except (OSError, ValueError, EOFError) as exc:  # a damaged file: no comments
            f.comments_error = f"could not read the packet comments: {exc}"
        finally:
            f.comments_ready.set()
        with self._lock:
            current = self._file is f
        if current and (f.comments or f.comments_error):
            self.notify("comments", {"count": len(f.comments), "error": f.comments_error})

    def _effective_comment(self, f: _Open, frame: int) -> str | None:
        if frame in self._comment_edits:
            return self._comment_edits[frame] or None
        texts = f.comments.get(frame)
        return "\n".join(texts) if texts else None

    def _add_comments(self, f: _Open, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            edits = self._comment_edits
        for row in rows:
            n = row["number"]
            text = self._effective_comment(f, n)
            if text:
                row["comment"] = text
            if n in edits:
                row["commentEdited"] = True

    def set_comments(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Replace the unsaved comment edits: ``edits`` maps frame numbers (as
        strings, JSON keys) to the new comment, ``null`` or ``""`` to delete it.
        Rows show them (``comment``, ``commentEdited``) until saved. ``reload:
        true`` reads the file's comments again first (another editor saved it)."""
        f = self._require_file()
        edits = _comment_edits(params, f.frame_count())
        if params.get("reload"):
            f.comments_ready.wait(60)
            try:
                saved = comments.read_comments(f.path)
            except (comments.UnreadableError, OSError, ValueError, EOFError):
                saved = f.comments
            with self._lock:
                f.comments = saved
                for cache in (self._details, self._quick, self._filters):
                    cache.clear()
        with self._lock:
            self._comment_edits = edits
        return {"edits": len(edits)}

    def packet_comments(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """The comments of ``frames`` (``all: true``: of every packet), edits
        included, and why the file's comments couldn't be read (``error``)."""
        f = self._require_file()
        f.comments_ready.wait(60)
        if params.get("all"):
            with self._lock:
                wanted = sorted(set(f.comments) | set(self._comment_edits))
        else:
            wanted = _frame_list(params, "frames", MAX_PAGE)
        found = {}
        for n in wanted:
            text = self._effective_comment(f, n)
            if text:
                found[str(n)] = text
        with self._lock:
            edited = [n for n in wanted if n in self._comment_edits]
        return {"comments": found, "edited": edited, "error": f.comments_error}

    def save_comments(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Write the capture with the comment edits applied (``edits``, default
        the unsaved ones) as pcapng: into the open capture itself with
        ``inPlace: true`` (plain pcapng only; the edits then become its
        comments), else to ``dest``. Needs editcap; the file appears only once
        complete."""
        f = self._require_file()
        if isinstance(f.capture, FollowFile) and not f.capture.ended.is_set():
            # (Another program is still writing the file, and its comments aren't all read.)
            raise InvalidParamsError("stop following the file before saving its comments")
        edits = _comment_edits(params, f.frame_count()) if "edits" in params else None
        with self._lock:
            if edits is None:
                edits = dict(self._comment_edits)
        f.comments_ready.wait(60)
        if f.comments_error:
            raise ToolError(f"comments can't be saved: {f.comments_error}")
        in_place = bool(params.get("inPlace"))
        if in_place and not comments.is_pcapng(f.path):
            raise InvalidParamsError("comments can only be saved into a pcapng file: save as")
        dest = f.path if in_place else check_destination(param(params, "dest", str), f.path)
        try:
            editcap = find_tool("editcap", sibling_of=f.tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError("saving comments needs editcap (part of Wireshark)") from exc
        args, result = comments.editcap_args(f.comments, edits)
        ctx.progress({"phase": "save", "fraction": None})
        if not in_place:
            with atomic_output(dest) as tmp:
                self._run_editcap(editcap, f.path, tmp, args, ctx)
            return {"path": str(dest), "comments": len(result)}
        tmp = dest.with_name(f".{dest.name}.{os.getpid()}.part")
        try:
            self._run_editcap(editcap, f.path, tmp, args, ctx)
            with self._lock:  # no pass starts on the old file meanwhile
                _replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)
        with self._lock:
            f.comments = {
                n: f.comments[n] if n in f.comments and n not in edits else [text]
                for n, text in result.items()
            }
            self._comment_edits = {}
            # Detail trees show the old comments; comment filters matched them.
            for cache in (self._details, self._quick, self._filters):
                cache.clear()
        return {"path": str(dest), "comments": len(result)}

    def _run_editcap(
        self, editcap: Path, src: Path, dest: Path, args: list[str], ctx: RequestContext
    ) -> None:
        """editcap ``args`` over ``src`` into ``dest`` (pcapng); several runs when
        the comments would make too long a command line (Windows). Only the
        first run discards the file's comments."""
        discard = [a for a in args if a == "--discard-packet-comments"]
        values = [args[i + 1] for i, a in enumerate(args) if a == "-a"]
        chunks: list[list[str]] = [[]]
        size = 0
        for value in values:
            if chunks[-1] and size + len(value) > MAX_FILTER_ARG:
                chunks.append([])
                size = 0
            chunks[-1].append(value)
            size += len(value) + 4
        source = src
        for i, chunk in enumerate(chunks):
            options = (discard if i == 0 else []) + [x for v in chunk for x in ("-a", v)]
            out = dest if i == len(chunks) - 1 else dest.with_name(f"{dest.name}.{i}")
            res = run([str(editcap), "-F", "pcapng", *options, str(source), str(out)], ctx.token)
            if source != src:
                source.unlink(missing_ok=True)
            if res.returncode != 0 or not out.exists():
                out.unlink(missing_ok=True)
                raise unwritable_error(res.stderr) or ToolError(
                    res.stderr.strip() or "editcap failed", res.stderr, res.returncode
                )
            source = out
