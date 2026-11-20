"""Cross-platform OS scheduler migration & retirement (`Task Scheduler`, `launchd`, `systemd`).

[Role]
Manages zero-console background schedule migration and Scale-to-Zero service
retirement across Windows Task Scheduler (`MindIEKimiUpdate`, `MindIE Diagnostics <hex>`),
macOS `launchd` (`agent.mindie.kimi-update`, `org.mindie.diagnostics.<12hex>` dual paths),
and Linux `systemd --user` timers, plus `discover_scheduled_executables` for GC closure.

[Invariants]
- Windows wrappers (`render_windows_gui_wrapper`) NEVER pass `CREATE_NEW_CONSOLE` or
  `DETACHED_PROCESS`; they require a verified `Subsystem == 2` (`WINDOWS_GUI`)
  `pythonw.exe` (`verify_gui_subsystem`), tolerate `sys.stdin/stdout/stderr is None`,
  and spawn children exclusively with `CREATE_NO_WINDOW (0x08000000)`.
- `launchd` plists always set `KeepAlive=False` (Scale-to-Zero).
- Retirement drains active OS services (`launchctl bootout` / `Unregister-ScheduledTask` /
  `systemctl --user disable --now`) and polls readback BEFORE old runtime venvs can be deleted.

[Timeouts & Locks]
- Scheduler registration and readback calls run under `15.0s–30.0s` `Deadline`s with
  a `3.0s` readback drain loop on retirement.

[Side-Effect Policy]
- Writes only caller-designated wrapper/plist/timer files and OS user-level schedules.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Sequence
import xml.etree.ElementTree as ET

from ..atomic import atomic_write_bytes, atomic_write_text
from ..paths import HarnessError, ProfileRef, config_home, diagnostics_root
from ..process.posix import which_posix_binary
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from ..process.win32 import verify_gui_subsystem

_QUOTED_PATH_RE = re.compile(r"""['"]([A-Za-z]:\\[^'"]+|/[^'"]+)['"]""")


def _default_systemd_user_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg and xdg.strip() else (Path.home() / ".config")
    return base / "systemd" / "user"


def _format_systemd_arg(arg: str) -> str:
    if not arg or any(ch.isspace() or ch in {'"', "'", "\\"} for ch in arg):
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return arg


def render_windows_gui_wrapper(command: Sequence[str], *, timeout_seconds: int = 1220) -> str:
    """Render a zero-console `.pyw` script using owned process-tree execution (`CREATE_NO_WINDOW` + Job Object)."""
    argv_list = [str(part) for part in command]
    return (
        "from __future__ import annotations\n"
        "import io, os, signal, subprocess, sys\n"
        "if sys.stdin is None:\n"
        "    sys.stdin = io.StringIO('')\n"
        "if sys.stdout is None:\n"
        "    sys.stdout = open(os.devnull, 'w', encoding='utf-8')\n"
        "if sys.stderr is None:\n"
        "    sys.stderr = open(os.devnull, 'w', encoding='utf-8')\n"
        f"_CMD = {argv_list!r}\n"
        f"_TIMEOUT = {int(timeout_seconds)}\n"
        "try:\n"
        "    from mindie_harness.api import ProcessSpec, run_owned\n"
        "except ImportError:\n"
        "    _NO_WIN = 0x08000000 if os.name == 'nt' else 0\n"
        "    p = subprocess.Popen(_CMD, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
        "        stderr=subprocess.DEVNULL, creationflags=_NO_WIN, start_new_session=(os.name != 'nt'))\n"
        "    try:\n"
        "        _rc = p.wait(timeout=_TIMEOUT)\n"
        "    except BaseException:\n"
        "        if os.name != 'nt':\n"
        "            try: os.killpg(p.pid, signal.SIGKILL)\n"
        "            except OSError: p.kill()\n"
        "        else:\n"
        "            subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)],\n"
        "                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n"
        "                creationflags=_NO_WIN, check=False)\n"
        "        raise SystemExit(124)\n"
        "    raise SystemExit(int(_rc))\n"
        "else:\n"
        "    res = run_owned(ProcessSpec(argv=tuple(_CMD), allowed_returncodes=None,\n"
        "        role='background_maintenance'), deadline=float(_TIMEOUT))\n"
        "    raise SystemExit(int(res.returncode or 0))\n"
    )


def _detect_scheduler_backend() -> str | None:
    if os.name == "nt":
        if shutil.which("schtasks") and shutil.which("powershell"):
            return "task-scheduler"
        return None
    if sys.platform == "darwin":
        if which_posix_binary("launchctl") and hasattr(os, "getuid"):
            return "launchd"
        return None
    if sys.platform.startswith("linux"):
        if which_posix_binary("systemctl"):
            return "systemd-user"
    return None


def _build_windows_task_xml(
    pythonw: Path,
    wrapper: Path,
    *,
    interval_seconds: int | None = 300,
) -> bytes:
    task = ET.Element("Task", xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task", version="1.2")
    triggers = ET.SubElement(task, "Triggers")
    if interval_seconds is not None and interval_seconds > 0:
        trig = ET.SubElement(triggers, "TimeTrigger")
        start = datetime.now() + timedelta(seconds=int(interval_seconds))
        ET.SubElement(trig, "StartBoundary").text = start.isoformat(timespec="seconds")
        mins = max(1, int(round(interval_seconds / 60)))
        ET.SubElement(ET.SubElement(trig, "Repetition"), "Interval").text = f"PT{mins}M"
    principal = ET.SubElement(ET.SubElement(task, "Principals"), "Principal", id="Author")
    ET.SubElement(principal, "LogonType").text = "InteractiveToken"
    settings = ET.SubElement(task, "Settings")
    ET.SubElement(settings, "MultipleInstancesPolicy").text = "IgnoreNew"
    ET.SubElement(settings, "Hidden").text = "true"
    action = ET.SubElement(ET.SubElement(task, "Actions", Context="Author"), "Exec")
    ET.SubElement(action, "Command").text = str(pythonw)
    ET.SubElement(action, "Arguments").text = subprocess.list2cmdline([str(wrapper)])
    buf_path_xml = ET.tostring(task, encoding="utf-16", xml_declaration=True)
    return buf_path_xml


def _verify_windows_task_readback(task_name: str, pythonw: Path, wrapper: Path) -> None:
    escaped = task_name.replace("'", "''")
    ps_script = (
        "$ErrorActionPreference='Stop'; "
        f"$xml = Export-ScheduledTask -TaskName '{escaped}' -ErrorAction Stop; "
        "$bytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$xml); "
        "$out = [Console]::OpenStandardOutput(); "
        "$out.Write($bytes, 0, $bytes.Length); $out.Flush()"
    )
    res = run_owned(
        ProcessSpec(
            argv=("powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_script),
            role="background_maintenance",
        ),
        deadline=Deadline.from_timeout(30.0),
    )
    try:
        actions = ET.fromstring(res.stdout.lstrip("\ufeff")).findall("./{*}Actions/{*}Exec")
    except ET.ParseError as exc:
        raise HarnessError(
            f"Scheduled task XML readback parse failed for {task_name}",
            stage="scheduler_verify",
            reason="schedule_readback_invalid",
        ) from exc
    expected_arg = subprocess.list2cmdline([str(wrapper)])
    if (
        len(actions) != 1
        or actions[0].findtext("{*}Command") != str(pythonw)
        or actions[0].findtext("{*}Arguments") != expected_arg
    ):
        raise HarnessError(
            f"Scheduled task {task_name} readback mismatch",
            stage="scheduler_verify",
            reason="schedule_readback_mismatch",
        )


def migrate_schedule(
    *,
    name: str,
    command: Sequence[str],
    work_dir: str | Path,
    interval_seconds: int | None = 300,
    plist_dir: str | Path | None = None,
    systemd_dir: str | Path | None = None,
    backend: str | None = None,
) -> dict[str, Any]:
    """Create or atomically migrate an OS user schedule to `command` (`KeepAlive=False`, zero-console)."""
    if not command:
        raise ValueError("command must be non-empty")
    chosen = backend or _detect_scheduler_backend()
    wdir = Path(work_dir)
    wdir.mkdir(parents=True, exist_ok=True, mode=0o700)

    if chosen == "task-scheduler":
        py_candidate = Path(command[0])
        pythonw = py_candidate if py_candidate.name.lower() == "pythonw.exe" else py_candidate.with_name("pythonw.exe")
        verify_gui_subsystem(pythonw)
        wrapper = wdir / f"{name}.pyw"
        atomic_write_text(wrapper, render_windows_gui_wrapper(command))
        xml_path = wdir / f"{name}.xml"
        atomic_write_bytes(xml_path, _build_windows_task_xml(pythonw, wrapper, interval_seconds=interval_seconds))
        run_owned(
            ProcessSpec(
                argv=("schtasks", "/Create", "/F", "/TN", name, "/XML", str(xml_path)),
                role="background_maintenance",
            ),
            deadline=Deadline.from_timeout(30.0),
        )
        _verify_windows_task_readback(name, pythonw, wrapper)
        return {"status": "scheduled", "backend": chosen, "task": name, "wrapper": str(wrapper), "pythonw": str(pythonw)}

    if chosen == "launchd":
        agents_root = Path(plist_dir) if plist_dir is not None else (Path.home() / "Library" / "LaunchAgents")
        agents_root.mkdir(parents=True, exist_ok=True)
        plist_path = agents_root / f"{name}.plist"
        plist_doc: dict[str, Any] = {
            "Label": name,
            "ProgramArguments": [str(part) for part in command],
            "KeepAlive": False,
            "RunAtLoad": False,
            "EnvironmentVariables": {
                "PATH": os.environ.get("PATH") or "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONUTF8": "1",
            },
            "StandardOutPath": os.devnull,
            "StandardErrorPath": os.devnull,
        }
        if interval_seconds is not None and interval_seconds > 0:
            plist_doc["StartInterval"] = int(interval_seconds)
        atomic_write_bytes(plist_path, plistlib.dumps(plist_doc))
        uid = os.getuid()
        run_owned(
            ProcessSpec(
                argv=("launchctl", "bootout", f"gui/{uid}/{name}"),
                allowed_returncodes=None,
                role="background_maintenance",
            ),
            deadline=Deadline.from_timeout(15.0),
        )
        run_owned(
            ProcessSpec(
                argv=("launchctl", "bootstrap", f"gui/{uid}", str(plist_path)),
                role="background_maintenance",
            ),
            deadline=Deadline.from_timeout(15.0),
        )
        return {"status": "scheduled", "backend": chosen, "label": name, "plist": str(plist_path)}

    if chosen == "systemd-user":
        unit_root = Path(systemd_dir) if systemd_dir is not None else _default_systemd_user_dir()
        unit_root.mkdir(parents=True, exist_ok=True)
        svc_path = unit_root / f"{name}.service"
        exec_line = " ".join(_format_systemd_arg(str(c)) for c in command)
        svc_body = (
            "[Unit]\n"
            f"Description=MindIE Managed Task ({name})\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "Environment=PYTHONUTF8=1\n"
            f"ExecStart={exec_line}\n"
        )
        atomic_write_text(svc_path, svc_body, mode=0o644)
        if interval_seconds is not None and interval_seconds > 0:
            timer_path = unit_root / f"{name}.timer"
            first_delay = min(60, max(1, int(interval_seconds)))
            timer_body = (
                "[Unit]\n"
                f"Description=MindIE Timer ({name})\n\n"
                "[Timer]\n"
                f"OnStartupSec={first_delay}s\n"
                f"OnActiveSec={first_delay}s\n"
                f"OnUnitActiveSec={int(interval_seconds)}s\n"
                "Persistent=true\n\n"
                "[Install]\n"
                "WantedBy=timers.target\n"
            )
            atomic_write_text(timer_path, timer_body, mode=0o644)
            run_owned(ProcessSpec(argv=("systemctl", "--user", "daemon-reload"), role="background_maintenance"), deadline=15.0)
            run_owned(
                ProcessSpec(argv=("systemctl", "--user", "enable", "--now", f"{name}.timer"), role="background_maintenance"),
                deadline=15.0,
            )
            return {"status": "scheduled", "backend": chosen, "unit": f"{name}.timer", "service": str(svc_path)}
        return {"status": "scheduled", "backend": chosen, "service": str(svc_path)}

    return {"status": "unsupported", "backend": None, "name": name}


def retire_schedule(
    *,
    name: str,
    plist_paths: Sequence[str | Path] = (),
    systemd_dir: str | Path | None = None,
    wrapper_dir: str | Path | None = None,
    backend: str | None = None,
) -> dict[str, Any]:
    """Stop, unregister, and drain an OS schedule BEFORE retiring its referenced venv."""
    chosen = backend or _detect_scheduler_backend()

    if chosen == "launchd" and hasattr(os, "getuid"):
        uid = os.getuid()
        target = f"gui/{uid}/{name}"
        candidates = [Path(p) for p in plist_paths] or [Path.home() / "Library" / "LaunchAgents" / f"{name}.plist"]
        run_owned(
            ProcessSpec(argv=("launchctl", "bootout", target), allowed_returncodes=None, role="background_maintenance"),
            deadline=15.0,
        )
        for plist in candidates:
            if plist.is_file():
                run_owned(
                    ProcessSpec(
                        argv=("launchctl", "bootout", f"gui/{uid}", str(plist)),
                        allowed_returncodes=None,
                        role="background_maintenance",
                    ),
                    deadline=15.0,
                )
        cutoff = time.monotonic() + 3.0
        absent = False
        while time.monotonic() < cutoff:
            chk = run_owned(
                ProcessSpec(argv=("launchctl", "print", target), allowed_returncodes=None, role="background_maintenance"),
                deadline=5.0,
            )
            if chk.returncode == 113 or chk.returncode != 0:
                absent = True
                break
            time.sleep(0.15)
        for plist in candidates:
            plist.unlink(missing_ok=True)
        return {"status": "unscheduled" if absent else "drain_timeout", "backend": chosen, "label": name}

    if chosen == "task-scheduler":
        escaped = name.replace("'", "''")
        ps_unreg = (
            "if (Get-ScheduledTask | Where-Object { "
            f"$_.TaskName -eq '{escaped}' -and $_.TaskPath -eq '\\' }}) {{ "
            f"Unregister-ScheduledTask -TaskName '{escaped}' -TaskPath '\\' -Confirm:$false -ErrorAction Stop }}"
        )
        run_owned(
            ProcessSpec(
                argv=("powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_unreg),
                allowed_returncodes=None,
                role="background_maintenance",
            ),
            deadline=30.0,
        )
        if wrapper_dir is not None:
            for ext in (".pyw", ".xml"):
                (Path(wrapper_dir) / f"{name}{ext}").unlink(missing_ok=True)
        return {"status": "unscheduled", "backend": chosen, "task": name}

    if chosen == "systemd-user":
        unit_root = Path(systemd_dir) if systemd_dir is not None else _default_systemd_user_dir()
        run_owned(
            ProcessSpec(
                argv=("systemctl", "--user", "disable", "--now", f"{name}.timer", f"{name}.service"),
                allowed_returncodes=None,
                role="background_maintenance",
            ),
            deadline=15.0,
        )
        for ext in (".timer", ".service"):
            (unit_root / f"{name}{ext}").unlink(missing_ok=True)
        return {"status": "unscheduled", "backend": chosen, "unit": name}

    return {"status": "unsupported", "backend": None, "name": name}


def _extract_paths_from_file(file_path: Path) -> set[Path]:
    found: set[Path] = set()
    try:
        if not file_path.is_file():
            return found
        if file_path.suffix == ".plist":
            data = plistlib.loads(file_path.read_bytes())
            if isinstance(data, dict):
                for arg in data.get("ProgramArguments") or ():
                    if isinstance(arg, str) and (arg.startswith("/") or (len(arg) > 2 and arg[1] == ":")):
                        found.add(Path(arg))
            return found
        if file_path.suffix == ".xml":
            raw = file_path.read_bytes()
            text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig", errors="replace")
            root = ET.fromstring(text.lstrip("\ufeff"))
            for exec_node in root.findall("./{*}Actions/{*}Exec"):
                cmd = exec_node.findtext("{*}Command")
                if cmd:
                    found.add(Path(cmd.strip()))
                args = exec_node.findtext("{*}Arguments") or ""
                for m in _QUOTED_PATH_RE.finditer(args):
                    found.add(Path(m.group(1)))
            return found
        text = file_path.read_text(encoding="utf-8-sig", errors="replace")
        if file_path.suffix == ".service":
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                for prefix in ("ExecStart=", "ExecStartPre=", "ExecStartPost=", "WorkingDirectory="):
                    if line.startswith(prefix):
                        rhs = line[len(prefix) :].lstrip("-@+:!| \t")
                        try:
                            tokens = shlex.split(rhs, posix=True)
                        except ValueError:
                            tokens = rhs.split()
                        for tok in tokens:
                            if tok.startswith("/") or (len(tok) > 2 and tok[1] == ":"):
                                found.add(Path(tok))
        for m in _QUOTED_PATH_RE.finditer(text):
            found.add(Path(m.group(1)))
    except TimeoutError:
        raise
    except (OSError, ValueError, plistlib.InvalidFileException, ET.ParseError):
        pass
    return found


def discover_scheduled_executables(
    *,
    profile: ProfileRef | None = None,
    extra_dirs: Sequence[str | Path] = (),
    task_names: Sequence[str] = (),
) -> set[Path]:
    """Return executable/script paths referenced by OS schedules so GC keeps their venvs alive."""
    paths: set[Path] = set()
    scan_dirs: list[Path] = [Path(d) for d in extra_dirs]
    diag_cfg_env = os.environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    diag_cfg_path = (
        Path(diag_cfg_env).expanduser()
        if diag_cfg_env
        else (profile.config_path.parent / "diagnostics.json" if profile is not None else config_home() / "diagnostics.json")
    )
    scan_dirs.extend(
        [
            diag_cfg_path.with_name(f"{diag_cfg_path.name}.state") / "service",
            diagnostics_root() / "service",
        ]
    )
    if profile is not None:
        scan_dirs.extend([profile.state_dir, profile.data_dir / "update"])
    if sys.platform == "darwin":
        scan_dirs.append(Path.home() / "Library" / "LaunchAgents")
    elif sys.platform.startswith("linux"):
        scan_dirs.append(_default_systemd_user_dir())

    for directory in scan_dirs:
        try:
            if not directory.is_dir():
                continue
            with os.scandir(directory) as it:
                for entry in it:
                    if not entry.is_file():
                        continue
                    lower = entry.name.lower()
                    if ("mindie" in lower or "kimi" in lower or "diagnostics" in lower or "reporter" in lower) and lower.endswith(
                        (".plist", ".pyw", ".xml", ".service", ".timer")
                    ):
                        paths.update(_extract_paths_from_file(Path(entry.path)))
                        for nested in list(paths):
                            if nested.suffix.lower() == ".pyw" and nested.is_file():
                                paths.update(_extract_paths_from_file(nested))
        except TimeoutError:
            raise
        except OSError:
            continue

    if os.name == "nt" and task_names and shutil.which("powershell"):
        explicit_names = [str(t).replace("'", "''") for t in task_names if str(t).strip()]
        quoted_list = ", ".join(f"'{n}'" for n in explicit_names)
        filter_expr = f"$_.TaskName -in @({quoted_list}) -or $_.TaskName -eq 'MindIEKimiUpdate' -or $_.TaskName -like 'MindIE*'"
        ps = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$tasks = Get-ScheduledTask -TaskPath '\\' | Where-Object {{ {filter_expr} }}; "
            "foreach ($t in $tasks) { "
            "$xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath; "
            "if ($xml) { $b=[Text.UTF8Encoding]::new($false).GetBytes([string]$xml + \"`n---MINDIE_TASK_SEP---`n\"); "
            "$o=[Console]::OpenStandardOutput(); $o.Write($b,0,$b.Length); $o.Flush() } }"
        )
        try:
            out = run_owned(
                ProcessSpec(
                    argv=("powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps),
                    allowed_returncodes=None,
                    role="background_maintenance",
                ),
                deadline=10.0,
            )
            if out is not None and out.returncode == 0 and out.stdout.strip():
                for raw_chunk in out.stdout.split("---MINDIE_TASK_SEP---"):
                    chunk = raw_chunk.strip().lstrip("\ufeff")
                    if not chunk:
                        continue
                    try:
                        root = ET.fromstring(chunk)
                    except ET.ParseError:
                        continue
                    for exec_node in root.findall("./{*}Actions/{*}Exec"):
                        cmd = exec_node.findtext("{*}Command")
                        if cmd:
                            paths.add(Path(cmd.strip()))
                        args_txt = exec_node.findtext("{*}Arguments") or ""
                        for m in _QUOTED_PATH_RE.finditer(args_txt):
                            arg_path = Path(m.group(1))
                            paths.add(arg_path)
                            if arg_path.suffix.lower() == ".pyw" and arg_path.is_file():
                                paths.update(_extract_paths_from_file(arg_path))
        except (TimeoutError, HarnessError, OSError):
            pass

    return paths
