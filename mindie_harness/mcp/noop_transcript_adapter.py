"""Inert pure-stdlib transcript adapter fallback for standalone `mindie-harness` profiles.

[Role]
Satisfies `mindie_knowledge.loop.cli.validate_config` and `load_transcript_adapter`
(`FileIdentity`, `identify`, `read_material`) when `mindie-harness` provisions an
engine outside a host plugin checkout (`install.py`, `wheelhouse`, `selftest`),
automatically superseded when a host plugin binds its native `<host>_transcript.py`.

[Invariants]
- 100% pure Python stdlib; zero external or sibling package imports.
- Never reads arbitrary files or returns unredacted host transcript bytes.

[Timeouts & Locks]
- Pure in-memory no-op (`< 0.1ms`); acquires no locks.

[Side-Effect Policy]
- Strictly read-only / no-op; writes zero files or environment state.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class FileIdentity:
    """Minimal compatible transcript `FileIdentity` descriptor."""

    path: str
    dev: int
    ino: int
    size: int
    mtime_ns: int
    anchor_len: int = 0
    anchor_digest: str = ""

    def anchor_for(self, _count: int) -> str | None:
        return None

    def serialize(self) -> str:
        return json.dumps(
            {
                "dev": self.dev,
                "ino": self.ino,
                "anchor_len": self.anchor_len,
                "anchor_digest": self.anchor_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def unserialize(_text: str, _path: str) -> "FileIdentity | None":
        return None


def identify(_path: Any) -> FileIdentity | None:
    """Standalone profiles have no host transcript stream attached."""
    return None


def same_file(_first: Any, _second: Any) -> bool:
    return False


def capture_source(_event: Any) -> None:
    return None


def history_source(_event: Any) -> None:
    return None


def read_material(_path: Any, *, start: int = 0, scan_until: int | None = None, **_kwargs: Any) -> tuple[str, dict[str, Any]]:
    """Return an empty public-transcript slice when no host adapter is bound."""
    _ = scan_until
    pos = max(0, int(start or 0))
    return "", {
        "start": pos,
        "end": pos,
        "digest": _EMPTY_SHA256,
        "identity": "",
        "more": False,
    }


read_increment = read_material

__all__ = [
    "FileIdentity",
    "capture_source",
    "history_source",
    "identify",
    "read_increment",
    "read_material",
    "same_file",
]
