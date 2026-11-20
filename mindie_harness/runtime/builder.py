"""Single-venv candidate runtime builder with `2.5 GiB` disk floor and zero self-bricking.

[Role]
Builds and validates candidate runtime generations (`prepare_candidate_runtime`)
directly at `<generations_dir>/<generation_key>`, enforcing a `2.5 GiB` free-space
floor, same-volume `UV_CACHE_DIR` hardlinking, adaptive `uv` concurrency under
memory-capped Jobs, and `mindie-candidate-check/1` smoke validation.

[Invariants]
- `MIN_BUILD_FREE_BYTES` (`2.5 GiB`) guards ONLY candidate venv builds—small
  receipt, config, and marker writes are NEVER blocked by the build disk floor.
- Single-venv build at the final generation path: no wasteful double-venv copy.
- Lock contention (`LockTimeoutError`) returns `status="deferred"` with
  `reportable=False` (`#362`).
- Clean non-zero builder/probe exits (`execution == "completed"`) retire the
  unfinished candidate directory and raise a retryable `failed_cleanly` error—NEVER
  writing a permanent local `unknown`/`suppressed` poison state (Iron Rule 2).

[Timeouts & Locks]
- Serializes per-generation builds via sibling `<generations_dir>/.prepare.<key>.lock`.
- Default build budget is `300.0s` (`240s` `uv` + `30s` smoke probe + `30s` grace).

[Side-Effect Policy]
- Writes only inside `<generations_dir>/<generation_key>`, its sibling build lock,
  and same-volume `.uv-cache` / `.trash.*` directories.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import time
from typing import Any, Literal, Sequence

from ..atomic import (
    atomic_write_json,
     atomic_write_text,
    configure_same_volume_uv_cache,
    read_json_safe,
    stage_retire_directory,
    sweep_trash_directories,
)
from ..locks import FileLock, LockTimeoutError
from ..paths import HarnessError, ProfileRef, resolve_base_cpython, venv_python_path
from ..process.posix import which_posix_binary
from ..process.supervisor import Deadline, ProcessExecutionError, ProcessSpec, coerce_deadline, run_owned
from ..process.win32 import probe_current_job, repair_venv_pythonw_if_needed, verify_gui_subsystem
from .registry import RuntimeSelection

MIN_BUILD_FREE_BYTES: int = int(2.5 * (1024 ** 3))  # 2,684,354,560 bytes (2.5 GiB)
CANDIDATE_RECEIPT_SCHEMA = "mindie-candidate-check/1"
BUILDING_SENTINEL = ".building"
DEFAULT_BUILD_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True)
class PreparedGeneration:
    """Validated or deferred candidate runtime generation."""

    status: Literal["validated", "reused", "deferred"]
    generation_key: str
    generation_dir: Path
    python_path: Path
    receipt_path: Path
    components: dict[str, dict[str, str]]
    reportable: bool = False
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "generation_key": self.generation_key,
            "generation_dir": str(self.generation_dir),
            "python": str(self.python_path),
            "receipt": str(self.receipt_path),
            "components": dict(self.components),
            "reportable": self.reportable,
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload


def _existing_ancestor(path: Path) -> Path:
    probe = Path(path).absolute()
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    return probe


def check_disk_floor(
    target_dir: str | Path,
    *,
    min_free_bytes: int = MIN_BUILD_FREE_BYTES,
    usage_fn: Callable[[str | Path], Any] = shutil.disk_usage,
) -> int:
    """Verify `target_dir`'s volume has at least `min_free_bytes` (`2.5 GiB`) free."""
    ancestor = _existing_ancestor(Path(target_dir))
    free_bytes = int(usage_fn(ancestor).free)
    if free_bytes < int(min_free_bytes):
        raise HarnessError(
            f"Insufficient disk space at {ancestor}: {free_bytes} bytes free, "
            f"need >= {min_free_bytes} bytes (2.5 GiB) for candidate runtime build",
            stage="disk_preflight",
            reason="insufficient_disk_space",
            submission_state="not_sent",
            retryable=True,
            reportable=False,
            details={"free_bytes": free_bytes, "required_bytes": int(min_free_bytes)},
        )
    return free_bytes


def _is_receipt_valid(gen_dir: Path) -> tuple[bool, Path | None, dict[str, Any]]:
    receipt_path = gen_dir / "runtime.json"
    if (gen_dir / BUILDING_SENTINEL).exists():
        return False, None, {}
    receipt = read_json_safe(receipt_path)
    if not isinstance(receipt, dict) or receipt.get("schema") != CANDIDATE_RECEIPT_SCHEMA:
        return False, None, {}
    validation = receipt.get("validation")
    if not isinstance(validation, dict) or validation.get("status") != "validated":
        return False, None, {}
    py_raw = receipt.get("python")
    if not isinstance(py_raw, str) or not py_raw.strip():
        return False, None, {}
    py_path = Path(py_raw)
    if not py_path.is_file():
        return False, None, {}
    if os.name == "nt":
        pyw = py_path.with_name("pythonw.exe")
        try:
            verify_gui_subsystem(pyw)
        except HarnessError:
            repair_venv_pythonw_if_needed(gen_dir / ".venv")
            try:
                verify_gui_subsystem(pyw)
            except HarnessError:
                return False, None, {}
    return True, py_path, receipt


def _resolve_uv_executable(env: dict[str, str]) -> str:
    if os.name == "nt":
        found = shutil.which("uv", path=env.get("PATH"))
        if found:
            return found
    else:
        posix_uv = which_posix_binary("uv", path_env=env.get("PATH"))
        if posix_uv is not None:
            return str(posix_uv)
    raise HarnessError(
        "Executable `uv` not found on native PATH",
        stage="runtime_build",
        reason="uv_not_found",
        submission_state="not_sent",
        retryable=False,
        reportable=False,
    )


def _adaptive_build_env(profile: ProfileRef, gen_dir: Path) -> dict[str, str]:
    env = configure_same_volume_uv_cache(
        gen_dir,
        os.environ,
        preferred=profile.data_dir / ".uv-cache",
    )
    job = probe_current_job()
    if job.memory_limit_bytes is not None and job.memory_limit_bytes <= 2 * (1024 ** 3):
        env.setdefault("UV_CONCURRENT_INSTALLS", "2")
        env.setdefault("UV_CONCURRENT_BUILDS", "1")
        env.setdefault("UV_CONCURRENT_DOWNLOADS", "2")
        env.setdefault("RAYON_NUM_THREADS", "2")
    return env


def _default_uv_builder(
    profile: ProfileRef,
    gen_dir: Path,
    venv_dir: Path,
    build_env: dict[str, str],
    deadline: Deadline,
    base_python: Path,
) -> None:
    uv_bin = _resolve_uv_executable(build_env)
    pyproject = profile.plugin_root / "pyproject.toml"
    wheelhouse = profile.plugin_root / "wheelhouse"
    env = dict(build_env, UV_PROJECT_ENVIRONMENT=str(venv_dir))
    if pyproject.is_file():
        cmd = [
            uv_bin,
            "--native-tls",
            "sync",
            "--no-editable",
            "--no-dev",
            "--python",
            str(base_python),
            "--project",
            str(profile.plugin_root),
        ]
        if (profile.plugin_root / "uv.lock").is_file():
            cmd.append("--locked")
        if wheelhouse.is_dir():
            cmd.extend(["--offline", "--find-links", str(wheelhouse)])
        run_owned(
            ProcessSpec(
                argv=tuple(cmd),
                cwd=profile.plugin_root,
                env=env,
                role="background_maintenance",
                memory_limit_bytes=None,  # uv decompression uses adaptive thread throttling
            ),
            deadline=deadline,
        )
        return

    req_file = profile.plugin_root / "runtime-requirements.txt"
    if not req_file.is_file() and not wheelhouse.is_dir():
        raise HarnessError(
            f"Plugin root {profile.plugin_root} is missing pyproject.toml, runtime-requirements.txt, and wheelhouse",
            stage="runtime_build",
            reason="missing_runtime_manifest",
            submission_state="not_sent",
            retryable=False,
            reportable=False,
        )

    run_owned(
        ProcessSpec(
            argv=(uv_bin, "venv", "--python", str(base_python), str(venv_dir)),
            env=env,
            role="background_maintenance",
            memory_limit_bytes=None,
        ),
        deadline=deadline,
    )
    venv_py = venv_python_path(venv_dir)
    install_cmd = [uv_bin, "--native-tls", "pip", "install", "--python", str(venv_py)]
    if req_file.is_file():
        install_cmd.extend(["-r", str(req_file)])
        overrides = profile.plugin_root / "runtime" / "active-overrides.txt"
        if overrides.is_file():
            install_cmd.extend(["-r", str(overrides), "--overrides", str(overrides)])
    else:
        install_cmd.append("mindie-harness")
    if wheelhouse.is_dir():
        install_cmd.extend(["--offline", "--find-links", str(wheelhouse)])
    run_owned(
        ProcessSpec(
            argv=tuple(install_cmd),
            cwd=profile.plugin_root,
            env=env,
            role="background_maintenance",
            memory_limit_bytes=None,
        ),
        deadline=deadline,
    )


def _venv_has_selftest(venv_dir: Path) -> bool:
    sites = [venv_dir / "Lib" / "site-packages"]
    lib_dir = venv_dir / "lib"
    if lib_dir.is_dir():
        sites.extend(lib_dir.glob("python*/site-packages"))
    return any((s / "mindie_harness" / "selftest.py").is_file() for s in sites if s.is_dir())


def _retire_failed_candidate(gen_dir: Path) -> None:
    try:
        stage_retire_directory(gen_dir)
        sweep_trash_directories(gen_dir.parent, budget_seconds=0.5)
    except TimeoutError:
        raise
    except OSError:
        pass


def prepare_candidate_runtime(
    profile: ProfileRef,
    *,
    selection: RuntimeSelection | None = None,
    python: str | Path | None = None,
    deadline: Deadline | float | None = None,
    lock_timeout: float = 0.0,
    builder_fn: Callable[[Path, Path, dict[str, str], Deadline], None] | None = None,
    usage_fn: Callable[[str | Path], Any] = shutil.disk_usage,
    smoke_imports: Sequence[str] = (),
) -> PreparedGeneration:
    """Build or reuse a single-venv candidate runtime generation safely."""
    resolved_selection = selection or RuntimeSelection.from_pins({})
    gen_key = resolved_selection.generation_key
    gen_dir = profile.generations_dir / gen_key
    venv_dir = gen_dir / ".venv"
    receipt_path = gen_dir / "runtime.json"
    expected_py = venv_python_path(venv_dir)
    resolved_deadline = (
        coerce_deadline(deadline)
        if deadline is not None
        else Deadline.from_timeout(DEFAULT_BUILD_TIMEOUT_SECONDS, cleanup_grace=15.0)
    )

    profile.generations_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    build_lock = FileLock(
        profile.generations_dir / f".prepare.{gen_key}.lock",
        exclusive=True,
        timeout=lock_timeout,
    )
    try:
        build_lock.acquire()
    except LockTimeoutError:
        return PreparedGeneration(
            status="deferred",
            generation_key=gen_key,
            generation_dir=gen_dir,
            python_path=expected_py,
            receipt_path=receipt_path,
            components=dict(resolved_selection.components),
            reportable=False,
            reason="lock_timeout",
        )

    try:
        valid, existing_py, existing_receipt = _is_receipt_valid(gen_dir)
        if valid and existing_py is not None:
            return PreparedGeneration(
                status="reused",
                generation_key=gen_key,
                generation_dir=gen_dir,
                python_path=existing_py,
                receipt_path=receipt_path,
                components=dict(existing_receipt.get("components") or resolved_selection.components),
                reportable=False,
            )

        if gen_dir.exists():
            _retire_failed_candidate(gen_dir)

        check_disk_floor(profile.generations_dir, usage_fn=usage_fn)
        gen_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        sentinel = gen_dir / BUILDING_SENTINEL
        atomic_write_text(sentinel, f"{os.getpid()}\n")

        build_env = _adaptive_build_env(profile, gen_dir)
        base_py = resolve_base_cpython(python, build_env)

        try:
            if builder_fn is not None:
                builder_fn(gen_dir, venv_dir, build_env, resolved_deadline)
            else:
                _default_uv_builder(profile, gen_dir, venv_dir, build_env, resolved_deadline, base_py)

            # Mid-build disk floor re-check before finalizing
            check_disk_floor(profile.generations_dir, usage_fn=usage_fn)

            built_py = venv_python_path(venv_dir)
            if not built_py.is_file():
                raise HarnessError(
                    f"Candidate build did not produce interpreter at {built_py}",
                    stage="candidate_probe",
                    reason="candidate_interpreter_missing",
                    submission_state="acknowledged",
                    retryable=True,
                    reportable=False,
                )
            if os.name == "nt":
                repair_venv_pythonw_if_needed(venv_dir, base_py)
                verify_gui_subsystem(built_py.with_name("pythonw.exe"))

            eff_smoke = tuple(smoke_imports) if smoke_imports or builder_fn is not None else ("mindie_harness",)
            probe_stmt = "import sys; " + "".join(f"import {mod}; " for mod in eff_smoke) + "print('OK')"
            probe_out = run_owned(
                ProcessSpec(
                    argv=(str(built_py), "-I", "-X", "utf8", "-c", probe_stmt),
                    env=build_env,
                    role="background_maintenance",
                ),
                deadline=Deadline.from_timeout(min(30.0, max(5.0, resolved_deadline.remaining()))),
            )
            if not probe_out.stdout.strip().endswith("OK"):
                raise HarnessError(
                    "Candidate smoke probe did not emit OK",
                    stage="candidate_probe",
                    reason="candidate_probe_failed",
                    submission_state="acknowledged",
                    retryable=True,
                    reportable=False,
                )

            if _venv_has_selftest(venv_dir):
                selftest_budget = min(45.0, max(10.0, resolved_deadline.remaining()))
                st_out = run_owned(
                    ProcessSpec(
                        argv=(
                            str(built_py),
                            "-I",
                            "-X",
                            "utf8",
                            "-m",
                            "mindie_harness.cli",
                            "--host",
                            profile.host,
                            "selftest",
                            "--mode",
                            "candidate",
                            "--json",
                        ),
                        env=build_env,
                        role="background_maintenance",
                        allowed_returncodes=None,
                    ),
                    deadline=Deadline.from_timeout(selftest_budget),
                )
                try:
                    st_doc = json.loads((st_out.stdout or "").strip().splitlines()[-1]) if (st_out.stdout or "").strip() else {}
                except ValueError:
                    st_doc = {}
                if st_out.returncode != 0 or st_doc.get("status") != "passed":
                    raise HarnessError(
                        f"Candidate selftest (--mode candidate) failed (rc={st_out.returncode})",
                        stage="candidate_probe",
                        reason="candidate_probe_failed",
                        submission_state="acknowledged",
                        retryable=True,
                        reportable=False,
                        details={"selftest": st_doc},
                    )

            receipt_payload = {
                "schema": CANDIDATE_RECEIPT_SCHEMA,
                "key": gen_key,
                "generation": str(gen_dir),
                "python": str(built_py),
                "components": dict(resolved_selection.components),
                "validation": {
                    "status": "validated",
                    "validated_at": time.time(),
                    "plugin_version": resolved_selection.plugin_version,
                    "source_sha256": resolved_selection.source_sha256,
                },
            }
            atomic_write_json(receipt_path, receipt_payload)
            sentinel.unlink(missing_ok=True)
            return PreparedGeneration(
                status="validated",
                generation_key=gen_key,
                generation_dir=gen_dir,
                python_path=built_py,
                receipt_path=receipt_path,
                components=dict(resolved_selection.components),
                reportable=False,
            )
        except ProcessExecutionError as exc:
            _retire_failed_candidate(gen_dir)
            raise HarnessError(
                f"Candidate runtime build exited cleanly with code {exc.outcome.returncode}; "
                "partial directory retired for clean retry",
                stage="runtime_build",
                reason="candidate_build_failed_cleanly",
                submission_state="acknowledged",
                retryable=True,
                reportable=False,
                details={"returncode": exc.outcome.returncode},
            ) from exc
        except BaseException:
            _retire_failed_candidate(gen_dir)
            raise
    finally:
        build_lock.release()
