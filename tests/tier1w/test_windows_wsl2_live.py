"""Tier 1W live Windows 11 + WSL2 kernel Job, zero-`conhost`/zero-popup, `.inuse` lease, and DrvFS tests.

Runnable via `pytest tests/tier1w` OR standalone `python tests/tier1w/test_windows_wsl2_live.py`
inside isolated temp directories on `4090` (Win11 + WSL2) and `lenovo` (Win11).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mindie_harness import (  # noqa: E402
    Deadline,
    HarnessError,
    ProcessExecutionError,
    ProcessSpec,
    ProfileRef,
    RuntimeSelection,
    activate_runtime,
    open_wal_database,
    prepare_runtime,
    run_owned,
)
from mindie_harness.locks import acquire_generation_lease  # noqa: E402
from mindie_harness.mcp.receipts import process_boot_signature  # noqa: E402
from mindie_harness.paths import is_wsl_drvfs, venv_python_path  # noqa: E402
from mindie_harness.process.posix import which_posix_binary  # noqa: E402
from mindie_harness.process.win32 import (  # noqa: E402
    probe_current_job,
    read_pe_subsystem,
    repair_venv_pythonw_if_needed,
    verify_gui_subsystem,
)
from mindie_harness.runtime.activation import reclaim_generations  # noqa: E402
from mindie_harness.runtime.scheduler import render_windows_gui_wrapper  # noqa: E402


def _win_snapshot_conhost_and_visible_windows() -> tuple[set[int], set[int]]:
    """Pure `ctypes` Toolhelp32 + `EnumWindows` snapshot (spawns ZERO subprocesses or `conhost.exe`!)."""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    parent_map: dict[int, int] = {}
    exe_map: dict[int, str] = {}
    if snap and snap != ctypes.c_void_p(-1).value:
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if k32.Process32FirstW(snap, ctypes.byref(entry)):
                while True:
                    pid = int(entry.th32ProcessID)
                    parent_map[pid] = int(entry.th32ParentProcessID)
                    exe_map[pid] = entry.szExeFile.lower()
                    if not k32.Process32NextW(snap, ctypes.byref(entry)):
                        break
        finally:
            k32.CloseHandle(snap)

    root_pid = os.getpid()
    tree_pids: set[int] = {root_pid}
    added = True
    while added:
        added = False
        for pid, ppid in parent_map.items():
            if ppid in tree_pids and pid not in tree_pids:
                tree_pids.add(pid)
                added = True

    conhosts = {pid for pid in tree_pids if exe_map.get(pid) == "conhost.exe"}

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u32.GetWindowThreadProcessId.restype = wintypes.DWORD
    visible_hwnds: set[int] = set()
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd: int, _lparam: int) -> bool:
        if u32.IsWindowVisible(hwnd):
            owner_pid = wintypes.DWORD(0)
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
            if int(owner_pid.value) in tree_pids:
                visible_hwnds.add(int(hwnd))
        return True

    u32.EnumWindows(WNDENUMPROC(_cb), 0)
    return conhosts, visible_hwnds


class Tier1WLiveSuite(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="mindie-t1w-case-")
        self.root = Path(self._tmp.name)
        self._saved_env = dict(os.environ)
        os.environ["MINDIE_CONFIG_HOME"] = str(self.root / "cfg")
        os.environ["MINDIE_DATA_HOME"] = str(self.root / "data")
        os.environ["MINDIE_DIAGNOSTICS_ROOT"] = str(self.root / "diag")
        os.environ["UV_CACHE_DIR"] = str(self.root / "uv-cache")

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved_env)
        self._tmp.cleanup()

    @unittest.skipUnless(os.name == "nt", "Windows 11 kernel Job & PE test")
    def test_win32_nested_job_kill_tree_memory_cap_and_priority(self) -> None:
        parent_job = probe_current_job()
        # 1. Background maintenance role attaches BELOW_NORMAL + 512 MiB cap + CpuRateControl
        out = run_owned(
            ProcessSpec(
                argv=(sys.executable, "-c", "import os; print('PID', os.getpid())"),
                role="background_maintenance",
                memory_limit_bytes=512 * 1024 * 1024,
                cpu_rate_percent=25,
            ),
            deadline=Deadline.from_timeout(15.0),
        )
        assert out.job_metadata is not None
        self.assertTrue(out.job_metadata["kill_on_job_close"])
        self.assertEqual(out.job_metadata["memory_limit_bytes"], 512 * 1024 * 1024)
        self.assertTrue(out.job_metadata["below_normal_priority"])
        self.assertIsInstance(parent_job.in_job, bool)

        # 2. Enforce 64 MiB Job memory limit: allocating 160 MiB inside child MUST fail!
        with self.assertRaises(ProcessExecutionError):
            run_owned(
                ProcessSpec(
                    argv=(sys.executable, "-c", "x = bytearray(160 * 1024 * 1024); print(len(x))"),
                    memory_limit_bytes=64 * 1024 * 1024,
                ),
                deadline=Deadline.from_timeout(15.0),
            )

        # 3. Parent-kill -> nested Job `KILL_ON_JOB_CLOSE` kills grandchild immediately!
        gc_pid_file = self.root / "grandchild.pid"
        ready_file = self.root / "ready.txt"
        inner_py = self.root / "inner_worker.py"
        middle_py = self.root / "middle_supervisor.py"

        inner_py.write_text(
            "import subprocess, sys, time\n"
            "from pathlib import Path\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], creationflags=0x08000000)\n"
            f"Path({str(gc_pid_file)!r}).write_text(str(p.pid), encoding='utf-8')\n"
            f"Path({str(ready_file)!r}).write_text('1', encoding='utf-8')\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        middle_py.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
            "from mindie_harness import ProcessSpec, run_owned\n"
            f"run_owned(ProcessSpec(argv=(sys.executable, {str(inner_py)!r})), deadline=60.0)\n",
            encoding="utf-8",
        )

        middle = subprocess.Popen(
            [sys.executable, str(middle_py)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not ready_file.is_file():
                time.sleep(0.05)
            self.assertTrue(ready_file.is_file(), "Grandchild did not start in time")
            gc_pid = int(gc_pid_file.read_text(encoding="utf-8").strip())
            self.assertIsNotNone(process_boot_signature(gc_pid))

            # Abruptly kill `middle` -> Windows kernel closes `middle`'s Job handle -> grandchild dies!
            middle.kill()
            middle.wait(timeout=5.0)
            wait_dead = time.monotonic() + 3.0
            while time.monotonic() < wait_dead and process_boot_signature(gc_pid) is not None:
                time.sleep(0.05)
            self.assertIsNone(process_boot_signature(gc_pid), "Grandchild survived parent kill!")
        finally:
            if middle.poll() is None:
                middle.kill()
                middle.wait(timeout=2.0)

    @unittest.skipUnless(os.name == "nt", "Windows 11 zero-conhost & PE Subsystem==2 test")
    def test_win32_zero_conhost_and_pe_subsystem_guard(self) -> None:
        real_py = Path(sys.executable)
        repair_venv_pythonw_if_needed(real_py.parent.parent)
        real_pyw = real_py.with_name("pythonw.exe")
        self.assertEqual(read_pe_subsystem(real_py), 3)
        self.assertTrue(real_pyw.is_file())
        self.assertEqual(read_pe_subsystem(real_pyw), 2)
        verify_gui_subsystem(real_pyw)

        # Copy CUI `python.exe` to `fake_pythonw.exe` -> MUST be rejected by `verify_gui_subsystem`!
        fake_pyw = self.root / "pythonw.exe"
        shutil.copy2(real_py, fake_pyw)
        with self.assertRaises(HarnessError) as ctx:
            verify_gui_subsystem(fake_pyw)
        self.assertEqual(ctx.exception.reason, "windowless_interpreter_invalid")

        # Pure ctypes Toolhelp32 + EnumWindows Oracle (zero observer-induced conhost!)
        before_conhosts, before_windows = _win_snapshot_conhost_and_visible_windows()

        # A. Pure `pythonw.exe` GUI execution (Subsystem == 2) spawns 0 `conhost.exe` even while alive!
        gui_hold = self.root / "gui_hold.pyw"
        gui_started = self.root / "gui_started.txt"
        gui_stop = self.root / "gui_stop.txt"
        gui_hold.write_text(
            "from pathlib import Path\nimport time\n"
            f"Path({str(gui_started)!r}).write_text('1', encoding='utf-8')\n"
            f"while not Path({str(gui_stop)!r}).exists():\n"
            "    time.sleep(0.02)\n",
            encoding="utf-8",
        )
        import threading

        gui_err: list[BaseException] = []

        def _run_gui() -> None:
            try:
                run_owned(ProcessSpec(argv=(str(real_pyw), str(gui_hold)), role="gui_worker"), deadline=15.0)
            except BaseException as exc:
                gui_err.append(exc)

        t = threading.Thread(target=_run_gui)
        t.start()
        try:
            wait_s = time.monotonic() + 5.0
            while time.monotonic() < wait_s and not gui_started.is_file():
                time.sleep(0.02)
            self.assertTrue(gui_started.is_file())
            mid_conhosts, mid_windows = _win_snapshot_conhost_and_visible_windows()
            self.assertEqual(mid_conhosts - before_conhosts, set(), f"GUI worker spawned conhost: {mid_conhosts - before_conhosts}")
            self.assertEqual(mid_windows - before_windows, set(), "GUI worker created visible window!")
        finally:
            gui_stop.write_text("stop", encoding="utf-8")
            t.join(timeout=5.0)
        self.assertEqual(gui_err, [])

        # B. `render_windows_gui_wrapper` invoking CUI child with `CREATE_NO_WINDOW`: 0 visible windows, 0 leaked conhost!
        marker_out = self.root / "gui_done.txt"
        wrapper_pyw = self.root / "task_wrapper.pyw"
        wrapper_pyw.write_text(
            render_windows_gui_wrapper(
                [str(real_py), "-c", f"from pathlib import Path; Path({str(marker_out)!r}).write_text('ok')"],
                timeout_seconds=30,
            ),
            encoding="utf-8",
        )
        run_owned(
            ProcessSpec(argv=(str(real_pyw), str(wrapper_pyw)), role="gui_worker"),
            deadline=Deadline.from_timeout(20.0),
        )
        self.assertEqual(marker_out.read_text(encoding="utf-8"), "ok")
        time.sleep(0.1)
        after_conhosts, after_windows = _win_snapshot_conhost_and_visible_windows()
        self.assertEqual(after_conhosts - before_conhosts, set(), f"Leaked conhost.exe: {after_conhosts - before_conhosts}")
        self.assertEqual(after_windows - before_windows, set(), "Created visible window!")

    @unittest.skipUnless(os.name == "nt", "Windows NTFS non-FILE_SHARE_DELETE .inuse lease test")
    def test_win32_inuse_lease_blocks_movefileex_gc_until_released(self) -> None:
        profile = ProfileRef.resolve(
            "kimi",
            plugin_root=self.root / "plugin",
            config_path=self.root / "cfg" / "kimi.json",
            data_dir=self.root / "data",
        )
        profile.plugin_root.mkdir(parents=True)

        def _copy_builder(_g: Path, venv_dir: Path, _env: dict, _dl: Deadline) -> None:
            py = venv_python_path(venv_dir)
            py.parent.mkdir(parents=True, exist_ok=True)
            src_cfg = Path(sys.prefix) / "pyvenv.cfg"
            if src_cfg.is_file():
                shutil.copy2(src_cfg, venv_dir / "pyvenv.cfg")
            shutil.copy2(sys.executable, py)
            shutil.copy2(Path(sys.executable).with_name("pythonw.exe"), py.with_name("pythonw.exe"))

        gens = []
        for idx in range(3):
            sel = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": str(idx) * 40}}, plugin_version=f"0.1.{idx}")
            gens.append(prepare_runtime(profile, selection=sel, builder_fn=_copy_builder))

        with acquire_generation_lease(gens[0].generation_dir):
            act = activate_runtime(profile, gens[2], run_gc=True)
            self.assertEqual(act.status, "active")
            self.assertTrue(gens[0].generation_dir.is_dir(), "Leased generation was deleted!")
            self.assertTrue(gens[0].python_path.is_file(), "Files inside leased generation were partially deleted!")
            assert act.gc_summary is not None
            self.assertEqual(act.gc_summary["deferred_dirs"], 1)

        gc2 = reclaim_generations(profile)
        self.assertEqual(gc2["reclaimed_dirs"], 1)
        self.assertFalse(gens[0].generation_dir.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "WSL2 / Linux mountinfo & 64-entry PATH test")
    def test_wsl2_64_entry_windows_path_and_live_drvfs_guard(self) -> None:
        win_entries: list[str] = []
        for i in range(64):
            d = self.root / f"Program Files (x86) Win {i}"
            d.mkdir()
            mz = d / "python3"
            mz.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
            mz.chmod(0o755)
            exe = d / "python3.exe"
            exe.write_bytes(b"MZ\x90\x00")
            exe.chmod(0o755)
            win_entries.append(str(d))

        full_path = os.pathsep.join([*win_entries, os.environ.get("PATH", "/usr/bin:/bin")])
        resolved = which_posix_binary("python3", path_env=full_path)
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertFalse(str(resolved).startswith(str(self.root)))

        if Path("/mnt/c").is_dir() and is_wsl_drvfs("/mnt/c"):
            with self.assertRaises(HarnessError) as ctx:
                open_wal_database("/mnt/c/Users/Public/mindie-unsafe-wal.sqlite3", create=True)
            self.assertEqual(ctx.exception.reason, "drvfs_unsafe_state_root")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tier1WLiveSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    print(
        json.dumps(
            {
                "platform": sys.platform,
                "tests_run": res.testsRun,
                "failures": len(res.failures),
                "errors": len(res.errors),
                "skipped": len(res.skipped),
                "ok": res.wasSuccessful(),
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0 if res.wasSuccessful() else 1)
