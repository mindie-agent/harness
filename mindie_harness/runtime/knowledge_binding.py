"""Authoritative content-addressed `knowledge` engine & 9-domain catalog provisioner.

[Role]
Implements `ensure_knowledge_binding` and `run_stop_capture` across all 7 MindIE
host plugins (`codex`, `cc`, `kimi`, `dsh`, `agy`, `wb`, `oc`):
- Provisions content-addressed `<config_home>/engines/<host>/<20hex>/<domain>.engine.json`
  across all 9 public corpora via `mindie_knowledge.loop.domain_catalog.prepare(...)`;
- Auto-resolves each host's native `transcript_adapter` from `plugin_root` (falling
  back to `noop_transcript_adapter.py` when standalone and upgrading automatically
  when a host `plugin_root` is supplied);
- Retires replaced service owners via `domain_catalog.retire_changed(..., include_default=True)`
  and heals legacy `.retired` or deleted generation paths;
- Enforces fast `< 100ms` zero-SQLite exit on disabled/out-of-scope `Stop` hooks and
  permanent revocation (`Admission.inspect(...)["status"] == "inactive"` -> never revived).

[Invariants]
- 100% pure Python stdlib at top-level import (`HAR-ABI`).
- Never overwrites an engine config file with altered bytes in place; every runtime
  or adapter change produces a distinct `<20hex>` content-addressed path.
- Never modifies `mindie-consent.json` and never creates `admission.sqlite3` on
  public reads or unauthorized/out-of-scope `Stop` events.

[Timeouts & Locks]
- Serializes `<host>.json` mutations under `.<host>.json.update.lock` (`<= 5.0s`).
- `run_stop_capture` bounds total execution under a single `Deadline(timeout_sec)`.

[Side-Effect Policy]
- Writes only content-addressed engine files, secondary domain authorities, and
  `<host>.json` pointers inside `<profile.config_path.parent>` and `<profile.data_dir>`.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from typing import Any

from ..atomic import atomic_write_json, atomic_write_text, read_json_safe
from ..locks import FileLock, LockTimeoutError
from ..paths import HarnessError, ProfileRef, assert_wal_safe_path, same_interpreter
from ..process.posix import which_posix_binary
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from .registry import parse_version_key

FRAME_PREFIX = "MINDIE_KBIND_JSON:"
GITLEAKS_VERSION = "8.30.1"
DEFAULT_DOMAIN = "vllm-ascend"

HOST_TRANSCRIPT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "codex": ("scripts/codex_transcript.py", "plugins/mindie-agent/scripts/codex_transcript.py"),
    "cc": ("scripts/transcript.py",),
    "kimi": ("scripts/kimi_transcript.py",),
    "dsh": ("scripts/dsh_transcript.py",),
    "agy": ("scripts/agy_transcript.py", "plugins/mindie-agent/scripts/agy_transcript.py"),
    "wb": ("scripts/wb_transcript.py", "plugins/mindie-agent/scripts/wb_transcript.py"),
    "oc": ("scripts/opencode_transcript.py", "plugins/mindie-agent/scripts/opencode_transcript.py"),
    "omp": ("scripts/omp_transcript.py",),
}


def _noop_adapter_path() -> Path:
    return (Path(__file__).resolve().parents[1] / "mcp" / "noop_transcript_adapter.py").resolve()


def _resolve_transcript_adapter(host: str, plugin_root: Path, previous_engine: Mapping[str, Any]) -> Path:
    for rel in HOST_TRANSCRIPT_CANDIDATES.get(host, ()):
        cand = (plugin_root / rel).resolve()
        if cand.is_file():
            return cand
    prev = previous_engine.get("transcript_adapter")
    if isinstance(prev, str) and Path(prev).is_absolute():
        prev_path = Path(prev)
        if prev_path.is_file() and prev_path.name != "noop_transcript_adapter.py":
            return prev_path.resolve()
    return _noop_adapter_path()


def deterministic_redactor_path(profile: ProfileRef) -> Path:
    system = platform.system().lower() or ("windows" if os.name == "nt" else sys.platform)
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, "x64")
    binary = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    return (profile.data_dir / "cache" / "gitleaks" / GITLEAKS_VERSION / f"{system}-{arch}" / binary).resolve()


def _resolve_redactor(profile: ProfileRef, *, install_redactor: bool) -> str:
    explicit = os.environ.get("MINDIE_REDACTOR_EXECUTABLE")
    if isinstance(explicit, str) and explicit.strip():
        cand = Path(explicit.strip()).expanduser()
        if cand.is_absolute() and cand.is_file():
            return str(cand.resolve())
    det_path = deterministic_redactor_path(profile)
    if det_path.is_file():
        return str(det_path)
    if install_redactor:
        try:
            from mindie_knowledge.loop.transcript_redaction import install_scanner

            return str(Path(install_scanner(cache=profile.data_dir / "cache" / "gitleaks")).resolve())
        except TimeoutError:
            raise
        except Exception:
            pass
    found = shutil.which("gitleaks") if os.name == "nt" else which_posix_binary("gitleaks")
    if found:
        return str(Path(found).resolve())
    return str(det_path)


def has_knowledge_package(python_executable: str | Path | None = None) -> bool:
    """Fast check (`< 0.5ms` for venvs) whether `mindie_knowledge.loop.domain_catalog` is installed."""
    target = Path(python_executable) if python_executable is not None else Path(sys.executable)
    if same_interpreter(target, sys.executable):
        try:
            return importlib.util.find_spec("mindie_knowledge.loop.domain_catalog") is not None
        except (ImportError, AttributeError, ValueError):
            return False
    if not target.is_file():
        return False
    venv_root = target.parent.parent
    site_dirs = [venv_root / "Lib" / "site-packages"]
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        site_dirs.extend(lib_dir.glob("python*/site-packages"))
    existing_sites = [d for d in site_dirs if d.is_dir()]
    for sdir in existing_sites:
        if (sdir / "mindie_knowledge" / "loop" / "domain_catalog.py").is_file():
            return True
    if any(any(sdir.glob("*.pth")) for sdir in existing_sites):
        try:
            out = run_owned(
                ProcessSpec(
                    argv=(str(target), "-I", "-X", "utf8", "-c", "import importlib.util as u; print(int(u.find_spec('mindie_knowledge.loop.domain_catalog') is not None))"),
                    role="background_maintenance",
                    allowed_returncodes=None,
                ),
                deadline=Deadline.from_timeout(5.0),
            )
            return out.returncode == 0 and out.stdout.strip() == "1"
        except (TimeoutError, OSError, HarnessError):
            return False
    return False


def _select_python(profile: ProfileRef, explicit: str | Path | None) -> Path:
    if explicit is not None:
        return Path(explicit)
    cfg = read_json_safe(profile.config_path)
    raw = cfg.get("python") if isinstance(cfg, Mapping) else None
    if isinstance(raw, str) and raw.strip() and Path(raw).is_file():
        return Path(raw)
    return Path(sys.executable)


def _is_inside(candidate: Path, root: Path) -> bool:
    try:
        c_norm = os.path.normcase(str(candidate.resolve(strict=False)))
        r_norm = os.path.normcase(str(root.resolve(strict=False)))
        if os.path.splitdrive(c_norm)[0] != os.path.splitdrive(r_norm)[0]:
            return False
        return os.path.commonpath((c_norm, r_norm)) == r_norm
    except (OSError, ValueError):
        return False


def _authorized_stop_scope(profile: ProfileRef, event: Mapping[str, Any]) -> tuple[str | None, str]:
    """Pure-stdlib `< 5ms` consent + `project_roots` check (zero SQLite, zero subprocesses)."""
    cfg = read_json_safe(profile.config_path)
    cfg_doc = cfg if isinstance(cfg, Mapping) else {}
    comm_raw = cfg_doc.get("community_config")
    comm_path = Path(comm_raw) if isinstance(comm_raw, str) and os.path.isabs(comm_raw) else (profile.config_path.parent / "mindie-community.json")
    comm = read_json_safe(comm_path)
    if not isinstance(comm, Mapping) or comm.get("schema") != "mindie-community-config/1" or comm.get("enabled") is not True:
        return None, "sharing-disabled"
    cons_raw = comm.get("consent_config") or cfg_doc.get("consent_config")
    cons_path = Path(cons_raw) if isinstance(cons_raw, str) and os.path.isabs(cons_raw) else profile.consent_path
    cons = read_json_safe(cons_path)
    if (
        not isinstance(cons, Mapping)
        or cons.get("schema") != "mindie-consent/1"
        or cons.get("choice") not in {"contribute", "local-only"}
        or not isinstance(cons.get("choice_revision"), str)
        or not cons["choice_revision"].strip()
    ):
        return None, "sharing-disabled"
    roots_raw = comm.get("project_roots")
    if not isinstance(roots_raw, list) or not roots_raw:
        return None, "sharing-disabled"
    roots = [Path(r).expanduser().resolve(strict=False) for r in roots_raw if isinstance(r, str) and os.path.isabs(r)]
    if not roots:
        return None, "sharing-disabled"

    candidates: list[Any] = [event.get(k) for k in ("cwd", "workspace", "workspace_root", "project_root", "directory")]
    wps = event.get("workspacePaths")
    if isinstance(wps, list):
        candidates.extend(wps)
    saw_candidate = False
    for item in candidates:
        if isinstance(item, str) and item.strip() and os.path.isabs(item):
            saw_candidate = True
            cand_path = Path(item).expanduser().resolve(strict=False)
            for root in roots:
                if _is_inside(cand_path, root):
                    return str(root), "authorized"
    return None, ("out-of-scope" if saw_candidate else "missing-cwd")


def _child_rpc(python_exe: Path, payload: dict[str, Any], *, deadline: Deadline) -> dict[str, Any]:
    outcome = run_owned(
        ProcessSpec(
            argv=(str(python_exe), "-I", "-X", "utf8", "-m", "mindie_harness.runtime.knowledge_binding"),
            stdin_bytes=(json.dumps(payload, ensure_ascii=True) + "\n").encode("utf-8"),
            role="foreground",
            allowed_returncodes=None,
        ),
        deadline=deadline,
    )
    for line in reversed((outcome.stdout or "").splitlines()):
        if line.startswith(FRAME_PREFIX):
            parsed = json.loads(line[len(FRAME_PREFIX) :])
            if isinstance(parsed, dict):
                if parsed.get("_harness_error"):
                    err = parsed["_harness_error"]
                    raise HarnessError(
                        str(err.get("message") or "knowledge binding failed"),
                        stage=str(err.get("stage") or "knowledge_binding"),
                        reason=str(err.get("reason") or "knowledge_binding_failed"),
                        retryable=bool(err.get("retryable", False)),
                        reportable=bool(err.get("reportable", False)),
                    )
                return parsed
    detail = (outcome.stderr or outcome.stdout or "").strip()[:400]
    raise HarnessError(
        f"Knowledge binding helper exited with code {outcome.returncode}: {detail}",
        stage="knowledge_binding",
        reason="knowledge_binding_failed",
        retryable=True,
        reportable=False,
    )


def _supports_disabled_capture_mode() -> bool:
    from mindie_knowledge import package_version

    try:
        return parse_version_key(str(package_version())) >= parse_version_key("0.13.25")
    except ValueError:
        return True


def _ensure_in_process(
    profile: ProfileRef,
    *,
    plugin_root: Path,
    python_exe: Path,
    install_redactor: bool,
    retire_previous: bool,
    include_default_feed: bool,
    already_locked: bool,
    force_public_transcript: bool = False,
) -> dict[str, Any]:
    from mindie_knowledge.loop import domain_catalog
    from mindie_knowledge.loop.cli import config_at, validate_config
    from mindie_knowledge.loop.handoff import prepare_schema
    from mindie_knowledge.loop.lifecycle import inspect_retirement

    lock = None
    if not already_locked:
        lock = FileLock(
            profile.config_path.with_name(f".{profile.config_path.name}.update.lock"),
            exclusive=True,
            timeout=5.0,
        )
        try:
            lock.acquire()
        except LockTimeoutError:
            return {"status": "deferred", "reason": "lock_timeout", "reportable": False}

    try:
        raw_cfg = read_json_safe(profile.config_path)
        current_cfg = dict(raw_cfg) if isinstance(raw_cfg, dict) else {}

        prev_eng_path_raw = current_cfg.get("engine_config")
        prev_eng_doc = read_json_safe(prev_eng_path_raw) if isinstance(prev_eng_path_raw, str) and prev_eng_path_raw.strip() else None
        if not isinstance(prev_eng_doc, dict):
            legacy_eng = read_json_safe(profile.config_path.with_name(f"{profile.config_path.stem}.engine.json"))
            prev_eng_doc = dict(legacy_eng) if isinstance(legacy_eng, dict) else {}

        env_root = os.environ.get("MINDIE_KNOWLEDGE_ROOT")
        prev_root = prev_eng_doc.get("root")
        if isinstance(env_root, str) and env_root.strip():
            knowledge_root = Path(env_root.strip()).expanduser().resolve(strict=False)
        elif isinstance(prev_root, str) and prev_root.strip() and not _is_inside(Path(prev_root), profile.generations_dir):
            knowledge_root = Path(prev_root).expanduser().resolve(strict=False)
        else:
            knowledge_root = (profile.data_dir / "knowledge").resolve(strict=False)

        assert_wal_safe_path(knowledge_root)
        assert_wal_safe_path(profile.admission_db.parent)

        adapter_py = _resolve_transcript_adapter(profile.host, plugin_root, prev_eng_doc)
        redactor_bin = _resolve_redactor(profile, install_redactor=install_redactor)
        has_host_adapter = adapter_py.name != "noop_transcript_adapter.py"
        capture_ready = has_host_adapter and (force_public_transcript or Path(redactor_bin).is_file())
        capture_mode = "public-transcript" if (capture_ready or not _supports_disabled_capture_mode()) else "disabled"
        comm_path = (profile.config_path.parent / "mindie-community.json").resolve(strict=False)
        consent_path = profile.consent_path.resolve(strict=False)
        admission_path = profile.admission_db.resolve(strict=False)

        default_engine: dict[str, Any] = {
            "root": str(knowledge_root),
            "domain": DEFAULT_DOMAIN,
            "domain_catalog": domain_catalog.SCHEMA,
            "capture_mode": capture_mode,
            "transcript_adapter": str(adapter_py),
            "redactor_executable": redactor_bin,
            "admission_path": str(admission_path),
            "community_config": str(comm_path),
            "product_validation": {
                "schema": "mindie-candidate-check/1",
                "status": "validated",
                "python": str(python_exe),
            },
        }
        prev_summary = prev_eng_doc.get("summary_command")
        if isinstance(prev_summary, list) and prev_summary and all(isinstance(x, str) and x for x in prev_summary):
            rebound_summary = list(prev_summary)
            first_name = Path(rebound_summary[0]).name.lower()
            if first_name.startswith("python") or _is_inside(Path(rebound_summary[0]), profile.generations_dir):
                rebound_summary[0] = str(python_exe)
            default_engine["summary_command"] = rebound_summary
        for extra_key in ("organizer_command", "worker_policy", "service_launch_context"):
            if extra_key in prev_eng_doc:
                default_engine[extra_key] = prev_eng_doc[extra_key]

        prev_feeds = prev_eng_doc.get("feeds")
        if isinstance(prev_feeds, list) and prev_feeds:
            default_engine["feeds"] = list(prev_feeds)
        elif include_default_feed:
            default_engine["feeds"] = [domain_catalog.get_domain_config(DEFAULT_DOMAIN).to_feed()]

        validate_config(default_engine)
        default_text = json.dumps(default_engine, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        engines_root = (profile.config_path.parent / "engines" / profile.host).resolve(strict=False)
        authorities_root = (profile.config_path.parent / "authorities" / profile.host).resolve(strict=False)
        default_hash = hashlib.sha256(default_text.encode("utf-8")).hexdigest()[:20]
        default_engine_path = engines_root / default_hash / f"{DEFAULT_DOMAIN}.engine.json"
        if not default_engine_path.is_file() or default_engine_path.read_text(encoding="utf-8") != default_text:
            atomic_write_text(default_engine_path, default_text)
        prepare_schema(default_engine_path)

        sanitized_routes: dict[str, str] = {}
        raw_routes = current_cfg.get("domain_configs")
        if isinstance(raw_routes, Mapping):
            for dom, route_raw in raw_routes.items():
                if not isinstance(dom, str) or dom == DEFAULT_DOMAIN or not isinstance(route_raw, str) or not Path(route_raw).is_absolute():
                    continue
                route_path = Path(route_raw)
                if not route_path.is_file() or _is_inside(route_path, profile.generations_dir):
                    continue
                try:
                    if inspect_retirement(route_path) is not None:
                        continue
                    loaded = config_at(route_path)
                    if loaded.get("domain") != dom:
                        continue
                except TimeoutError:
                    raise
                except Exception:
                    continue
                sanitized_routes[dom] = str(route_path.resolve())

        catalog_report = domain_catalog.prepare(
            {"engine_config": str(default_engine_path), "domain_configs": sanitized_routes},
            default_engine,
            config_directory=str(engines_root),
            authority_directory=str(authorities_root),
            consent_config=str(consent_path),
            public_feeds=True,
        )
        new_routes = dict(catalog_report["domain_configs"])
        new_routes[DEFAULT_DOMAIN] = str(default_engine_path)

        retirement_report: dict[str, Any] | None = None
        if retire_previous:
            retire_prev_routes: dict[str, str] = {}
            if isinstance(raw_routes, Mapping):
                for dom, route_raw in raw_routes.items():
                    if isinstance(dom, str) and isinstance(route_raw, str) and Path(route_raw).is_file():
                        try:
                            if config_at(route_raw).get("domain") == dom:
                                retire_prev_routes[dom] = str(Path(route_raw).resolve())
                        except TimeoutError:
                            raise
                        except Exception:
                            continue
            retire_prev_doc: dict[str, Any] = {"domain_configs": retire_prev_routes}
            if isinstance(prev_eng_path_raw, str) and Path(prev_eng_path_raw).is_file():
                try:
                    config_at(prev_eng_path_raw)
                    retire_prev_doc["engine_config"] = str(Path(prev_eng_path_raw).resolve())
                except TimeoutError:
                    raise
                except Exception:
                    pass
            retirement_report = domain_catalog.retire_changed(
                retire_prev_doc,
                {"engine_config": str(default_engine_path), "domain_configs": new_routes},
                timeout=15.0,
                include_default=True,
            )
            if retirement_report.get("status") not in {"retired", "completed"}:
                reason = (
                    "knowledge_service_busy"
                    if retirement_report.get("status") == "deferred"
                    else "knowledge_retirement_incomplete"
                )
                return {
                    "status": "deferred",
                    "reason": reason,
                    "reportable": False,
                    "retirement": retirement_report,
                }

        binding_fields = {
            "host": profile.host,
            "engine_config": str(default_engine_path),
            "domain_configs": new_routes,
            "community_config": str(comm_path),
            "consent_config": str(consent_path),
            "admission_path": str(admission_path),
        }
        if not already_locked:
            merged_cfg = dict(current_cfg)
            merged_cfg.setdefault("python", str(python_exe))
            merged_cfg.setdefault("source_root", str(plugin_root))
            merged_cfg.update(binding_fields)
            merged_cfg["updated_at"] = time.time()
            try:
                atomic_write_json(profile.config_path, merged_cfg)
            except Exception:
                if retirement_report is not None:
                    try:
                        domain_catalog.restore_changed(retirement_report, timeout=5.0)
                    except Exception:
                        pass
                raise

        # Only prune after <host>.json is published (!already_locked), always protecting
        # active + rollback (old_routes) + 18 recent dirs (2 generations * 9 domains).
        if not already_locked and engines_root.is_dir():
            referenced_dirs = {Path(p).parent.resolve() for p in new_routes.values()}
            referenced_dirs.add(default_engine_path.parent.resolve())
            old_default = current_cfg.get("engine_config")
            if isinstance(old_default, str) and old_default:
                referenced_dirs.add(Path(old_default).parent.resolve())
            for old_p in (current_cfg.get("domain_configs") or {}).values():
                if isinstance(old_p, str) and old_p:
                    referenced_dirs.add(Path(old_p).parent.resolve())
            unreferenced: list[tuple[float, Path]] = []
            for child in engines_root.iterdir():
                if child.is_dir() and child.resolve() not in referenced_dirs:
                    try:
                        unreferenced.append((child.stat().st_mtime, child))
                    except OSError:
                        continue
            unreferenced.sort(key=lambda item: item[0], reverse=True)
            for _, stale_dir in unreferenced[18:]:
                shutil.rmtree(stale_dir, ignore_errors=True)

        return {
            "status": "configured",
            "engine_config": str(default_engine_path),
            "domain_configs": new_routes,
            "domains": sorted(new_routes),
            "capture_mode": capture_mode,
            "transcript_adapter": str(adapter_py),
            "standalone_adapter": adapter_py.name == "noop_transcript_adapter.py",
            "redactor_executable": redactor_bin,
            "binding_fields": binding_fields,
            "retirement": retirement_report,
            "reportable": False,
        }
    finally:
        if lock is not None:
            lock.release()


def ensure_knowledge_binding(
    profile: ProfileRef,
    *,
    plugin_root: Path | None = None,
    python_executable: str | Path | None = None,
    install_redactor: bool = False,
    retire_previous: bool = False,
    include_default_feed: bool = False,
    already_locked: bool = False,
) -> dict[str, Any]:
    """Provision content-addressed `<host>` default + 8 secondary domain engine configs."""
    eff_plugin_root = Path(plugin_root).resolve() if plugin_root is not None else profile.plugin_root.resolve()
    eff_python = _select_python(profile, python_executable)
    if not has_knowledge_package(eff_python):
        return {"status": "skipped", "reason": "knowledge_not_installed", "reportable": False}
    if not same_interpreter(eff_python, sys.executable):
        return _child_rpc(
            eff_python,
            {
                "op": "ensure_binding",
                "host": profile.host,
                "plugin_root": str(eff_plugin_root),
                "config_path": str(profile.config_path),
                "data_dir": str(profile.data_dir),
                "python_executable": str(eff_python),
                "install_redactor": bool(install_redactor),
                "retire_previous": bool(retire_previous),
                "include_default_feed": bool(include_default_feed),
                "already_locked": bool(already_locked),
            },
            deadline=Deadline.from_timeout(45.0 if install_redactor or retire_previous else 25.0, cleanup_grace=5.0),
        )
    return _ensure_in_process(
        profile,
        plugin_root=eff_plugin_root,
        python_exe=eff_python,
        install_redactor=install_redactor,
        retire_previous=retire_previous,
        include_default_feed=include_default_feed,
        already_locked=already_locked,
    )


def restore_knowledge_retirement(
    profile: ProfileRef,
    retirement_report: Mapping[str, Any] | None,
    *,
    python_executable: str | Path | None = None,
) -> dict[str, Any] | None:
    """Best-effort rollback of `retire_changed` if final `<host>.json` publication fails."""
    if not isinstance(retirement_report, Mapping) or not retirement_report.get("domains"):
        return None
    eff_python = _select_python(profile, python_executable)
    if not has_knowledge_package(eff_python):
        return None
    if not same_interpreter(eff_python, sys.executable):
        return _child_rpc(
            eff_python,
            {
                "op": "restore_retirement",
                "host": profile.host,
                "plugin_root": str(profile.plugin_root),
                "config_path": str(profile.config_path),
                "data_dir": str(profile.data_dir),
                "retirement": dict(retirement_report),
            },
            deadline=Deadline.from_timeout(10.0, cleanup_grace=2.0),
        )
    from mindie_knowledge.loop import domain_catalog

    return domain_catalog.restore_changed(dict(retirement_report), timeout=5.0)


def _stop_in_process(
    profile: ProfileRef,
    event: Mapping[str, Any],
    *,
    matched_root: str,
    plugin_root: Path,
    deadline: Deadline,
) -> dict[str, Any]:
    from mindie_knowledge.loop.activation import Admission
    from mindie_knowledge.loop.cli import config_at
    from mindie_knowledge.loop.handoff import accept_stop
    from mindie_knowledge.loop.lifecycle import inspect_retirement

    session_id = event.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip() or len(session_id.strip()) > 256:
        return {"stage": "rejected", "reason": "missing-identity"}
    session_id = session_id.strip()

    cfg = read_json_safe(profile.config_path)
    cfg_doc = cfg if isinstance(cfg, Mapping) else {}
    eng_raw = cfg_doc.get("engine_config")
    eng_path = Path(eng_raw) if isinstance(eng_raw, str) and eng_raw.strip() else None

    needs_provision = eng_path is None or not eng_path.is_file()
    retire_replaced = False
    if not needs_provision and eng_path is not None:
        try:
            if inspect_retirement(eng_path) is not None:
                needs_provision = True
            else:
                loaded_eng = config_at(eng_path)
                cur_adapter = Path(str(loaded_eng.get("transcript_adapter") or ""))
                cur_redactor = Path(str(loaded_eng.get("redactor_executable") or ""))
                if (
                    loaded_eng.get("capture_mode") == "disabled"
                    or cur_adapter.name == "noop_transcript_adapter.py"
                    or not cur_redactor.is_file()
                ):
                    resolved_cand = _resolve_transcript_adapter(profile.host, plugin_root, loaded_eng)
                    resolved_red = Path(_resolve_redactor(profile, install_redactor=False))
                    if resolved_cand.name != "noop_transcript_adapter.py" and (
                        loaded_eng.get("capture_mode") == "disabled"
                        or cur_adapter.name == "noop_transcript_adapter.py"
                        or (not cur_redactor.is_file() and resolved_red.is_file())
                    ):
                        needs_provision = True
                        retire_replaced = True
        except TimeoutError:
            raise
        except Exception:
            needs_provision = True

    if needs_provision:
        ensured = _ensure_in_process(
            profile,
            plugin_root=plugin_root,
            python_exe=Path(sys.executable),
            install_redactor=False,
            retire_previous=retire_replaced,
            include_default_feed=False,
            already_locked=False,
            force_public_transcript=True,
        )
        if ensured.get("status") != "configured":
            return {"stage": "unavailable", "reason": str(ensured.get("reason") or "configuration")}
        eng_path = Path(ensured["engine_config"])

    assert eng_path is not None
    engine_cfg = config_at(eng_path)
    work_deadline = deadline.expires_at - deadline.cleanup_grace
    if time.monotonic() >= work_deadline:
        return {"stage": "unavailable", "reason": "budget-exhausted"}

    admission = Admission(engine_cfg["admission_path"])
    inspected = admission.inspect(session_id, deadline=work_deadline)
    if inspected.get("status") == "inactive":
        return {"stage": "inert", "reason": "revoked"}
    if inspected.get("status") == "unavailable":
        return {"stage": "unavailable", "reason": str(inspected.get("cause") or "admission-unreadable")}

    lease = admission.active_lease(session_id, deadline=work_deadline)
    if (lease is None or not lease.get("entry_enabled")) and inspected.get("status") == "missing":
        lease = admission.activate(
            session_id,
            project_root=matched_root,
            root_session=session_id,
            not_before=0.0,
        )
    if lease is None or not lease.get("token") or not lease.get("entry_enabled"):
        return {"stage": "inert", "reason": "not-activated"}
    if engine_cfg.get("capture_mode") == "disabled":
        return {"stage": "inert", "reason": "capture-disabled"}

    stop_event = dict(event)
    stop_event["hook_event_name"] = "Stop"
    stop_event["session_id"] = session_id
    stop_event.setdefault("harness", profile.host)
    if not stop_event.get("identity_kind"):
        if isinstance(stop_event.get("turn_id"), str) and stop_event["turn_id"].strip() and not stop_event.get("event_id"):
            stop_event["identity_kind"] = "turn"
        elif isinstance(stop_event.get("event_id"), str) and stop_event["event_id"].strip():
            stop_event["identity_kind"] = "notification"
    if stop_event.get("identity_kind") == "notification":
        stop_event.pop("last_assistant_message", None)
    stop_event["mindie_activation"] = str(lease["token"])
    return accept_stop(eng_path, stop_event, deadline=work_deadline)


def run_stop_capture(
    profile: ProfileRef,
    event: Mapping[str, Any],
    *,
    plugin_root: Path | None = None,
    timeout_sec: float = 6.0,
) -> dict[str, Any]:
    """Fast consent-gated `Stop` capture helper honoring permanent user revocation."""
    if not isinstance(event, Mapping):
        return {"stage": "inert", "reason": "not-stop"}
    if event.get("stop_hook_active", False) is not False:
        return {"stage": "inert", "reason": "recursive-stop"}
    matched_root, scope_reason = _authorized_stop_scope(profile, event)
    if matched_root is None:
        return {"stage": "inert", "reason": scope_reason}

    total = max(1.0, float(timeout_sec))
    grace = min(0.5, total * 0.1)
    deadline = Deadline.from_timeout(total, cleanup_grace=grace)
    eff_plugin_root = Path(plugin_root).resolve() if plugin_root is not None else profile.plugin_root.resolve()
    eff_python = _select_python(profile, None)
    if not has_knowledge_package(eff_python):
        return {"stage": "unavailable", "reason": "knowledge-not-installed"}

    if not same_interpreter(eff_python, sys.executable):
        rem = deadline.inner_remaining()
        if rem <= 0:
            return {"stage": "unavailable", "reason": "budget-exhausted"}
        return _child_rpc(
            eff_python,
            {
                "op": "stop_capture",
                "host": profile.host,
                "plugin_root": str(eff_plugin_root),
                "config_path": str(profile.config_path),
                "data_dir": str(profile.data_dir),
                "matched_root": matched_root,
                "timeout_sec": rem,
                "event": dict(event),
            },
            deadline=deadline,
        )
    return _stop_in_process(
        profile,
        event,
        matched_root=matched_root,
        plugin_root=eff_plugin_root,
        deadline=deadline,
    )


def _cli_main() -> int:
    raw = sys.stdin.buffer.read(4 * 1024 * 1024)
    req = json.loads(raw.decode("utf-8-sig"))
    profile = ProfileRef.resolve(
        str(req["host"]),
        plugin_root=req.get("plugin_root"),
        config_path=req.get("config_path"),
        data_dir=req.get("data_dir"),
    )
    try:
        if req.get("op") == "ensure_binding":
            res = _ensure_in_process(
                profile,
                plugin_root=Path(req["plugin_root"]),
                python_exe=Path(req.get("python_executable") or sys.executable),
                install_redactor=bool(req.get("install_redactor")),
                retire_previous=bool(req.get("retire_previous")),
                include_default_feed=bool(req.get("include_default_feed")),
                already_locked=bool(req.get("already_locked")),
            )
        elif req.get("op") == "stop_capture":
            total = max(1.0, float(req.get("timeout_sec") or 6.0))
            res = _stop_in_process(
                profile,
                req.get("event") or {},
                matched_root=str(req["matched_root"]),
                plugin_root=Path(req["plugin_root"]),
                deadline=Deadline.from_timeout(total, cleanup_grace=min(0.25, total * 0.1)),
            )
        elif req.get("op") == "restore_retirement":
            from mindie_knowledge.loop import domain_catalog

            res = domain_catalog.restore_changed(dict(req.get("retirement") or {}), timeout=5.0)
        else:
            raise ValueError(f"Unknown knowledge_binding op: {req.get('op')!r}")
    except HarnessError as exc:
        res = {"_harness_error": exc.to_dict()}
    sys.stdout.buffer.write((FRAME_PREFIX + json.dumps(res, ensure_ascii=True) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


__all__ = [
    "DEFAULT_DOMAIN",
    "HOST_TRANSCRIPT_CANDIDATES",
    "deterministic_redactor_path",
    "ensure_knowledge_binding",
    "has_knowledge_package",
    "restore_knowledge_retirement",
    "run_stop_capture",
]

if __name__ == "__main__":
    raise SystemExit(_cli_main())
