"""Module execution entrypoint (`python -m mindie_harness`) for `mindie-harness`.

[Role]
Forwards `python -m mindie_harness ...` directly to `mindie_harness.cli:main`.

[Invariants]
- Zero import-time side effects; delegates argument parsing and exit code handling to `main()`.

[Timeouts & Locks]
- Governed by the selected `mindie_harness.cli` subcommand.

[Side-Effect Policy]
- Same as `mindie_harness.cli:main`.
"""
from __future__ import annotations

from mindie_harness.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
