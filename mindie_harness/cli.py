"""CLI entrypoint (`mindie-harness` & `python -I -X utf8 -m mindie_harness.cli`).

[Role]
Forwards console-script and `-m mindie_harness.cli` invocations directly to
`mindie_harness.api.run_host` so `mindie-bench` `upgrade_acceptance.py` and all
thin host plugin launchers share one canonical entrypoint.

[Invariants]
- Zero heavy imports; `< 15ms` cold execution for `--version` and `inspect`.

[Timeouts & Locks]
- Owned by `mindie_harness.api.run_host`.

[Side-Effect Policy]
- Pure delegation to `run_host`.
"""
from __future__ import annotations

from collections.abc import Sequence

from .api import run_host


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entrypoint for `mindie-harness`."""
    return run_host(argv)


if __name__ == "__main__":
    raise SystemExit(main())
