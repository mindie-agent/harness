"""Contract tests for the harness-backed natural-language RSI package.

[Role]
  Verify plan validation, bounded candidate execution, runtime installation, and
  the reference adapter that preserve the original MindIE Agent RSI behavior.
[Invariants]
  Unsafe shell payloads fail closed, evidence gates control promotion, and
  unknown external effects never trigger an automatic retry.
[Timeouts & Locks]
  Tier 1 local tests use only pytest temporary directories and short subprocesses.
[Side-Effect Policy]
  All files, bindings, and subprocesses stay below pytest ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from mindie_harness.rsi.natural_language import rsi_autotune
from mindie_harness.rsi.natural_language import rsi_compare
from mindie_harness.rsi.natural_language import rsi_cost_model
from mindie_harness.rsi.natural_language import rsi_defaults
from mindie_harness.rsi.natural_language import rsi_entry
from mindie_harness.rsi.natural_language import rsi_evidence
from mindie_harness.rsi.natural_language import rsi_install
from mindie_harness.rsi.natural_language import rsi_plan
from mindie_harness.rsi.natural_language import rsi_runtime_adapter
from mindie_harness.rsi.natural_language import rsi_simulation
from mindie_harness.rsi.natural_language import rsi_trend
from mindie_harness.rsi.natural_language import rsi_workload

SCRIPTS = Path(__file__).resolve().parents[2] / "mindie_harness/rsi/natural_language"
discover_startup_parameter = rsi_workload.discover_startup_parameter

def base_plan():
    return {
        "schema": rsi_plan.SCHEMA,
        "task_id": "decode-latency",
        "endpoint": {"host": "<remote-host>", "port": 22, "user": "root"},
        "source_root": "/home/user/model",
        "rsi_root": "/home/user/RSI",
        "startup_script": "/home/user/model/start.sh",
        "test_script": "/home/user/model/benchmark.sh",
        "baseline": "baseline-control",
        "objective": "maximize throughput",
        "operations": ["doctor", "profile", "accuracy", "performance"],
        "parallel_workers": 2,
        "devices": ["0", "1"],
        "payload": {},
    }


def test_validate_normalizes_defaults_and_render_requires_lease():
    plan = rsi_plan.validate(base_plan())
    assert plan["endpoint"]["user"] == "root"
    rendered = rsi_plan.render(plan)
    assert rendered["steps"][0]["tool"] == "remote_write"
    assert json.loads(rendered["steps"][0]["arguments"]["content"])["source_root"] == "/home/user/model"
    rendered_payload = json.loads(rendered["steps"][0]["arguments"]["content"])
    assert rendered_payload["startup_script"] == "/home/user/model/start.sh"
    assert rendered_payload["test_script"] == "/home/user/model/benchmark.sh"
    assert rendered["steps"][2]["requires"] == ["coordinator.lease"]
    assert rendered_payload["defaults"]["profile_binding"]["tool"] == "msprof"
    assert rendered_payload["defaults"]["optimization_scope"]["parameters"]["num_speculative_tokens"] == "adaptive"
    assert rendered_payload["defaults"]["optimization_scope"]["strategy"] == "trend_bound"
    assert rendered_payload["defaults"]["candidate_order"] == [
        "runtime_parameters", "startup_features"
    ]
    assert rendered_payload["algorithm_exploration_authorized"] is False


@pytest.mark.parametrize("field", ["source_root", "rsi_root"])
def test_remote_paths_cannot_escape_root(field):
    plan = base_plan()
    plan[field] = "/home/user/../secret"
    with pytest.raises(rsi_plan.PlanError, match="absolute remote path"):
        rsi_plan.validate(plan)


def test_shell_payload_is_rejected():
    plan = base_plan()
    plan["payload"] = {"command": "rm -rf /"}
    with pytest.raises(rsi_plan.PlanError, match="shell fields"):
        rsi_plan.validate(plan)


def test_startup_and_test_inputs_are_required():
    plan = base_plan()
    del plan["startup_script"]
    del plan["test_script"]
    with pytest.raises(rsi_plan.MissingInputError) as exc:
        rsi_plan.validate(plan)
    assert exc.value.fields == ("startup_script", "test_script or test_config or test_description or test_command")


def test_test_config_can_replace_test_script():
    plan = base_plan()
    del plan["test_script"]
    plan["test_config"] = "/home/user/model/benchmark.json"
    normalized = rsi_plan.validate(plan)
    assert normalized["test_config"] == "/home/user/model/benchmark.json"
    assert normalized["test_script"] is None


def test_test_description_can_replace_file_inputs():
    plan = base_plan()
    del plan["test_script"]
    plan["test_description"] = "Run vLLM serving benchmark with batch size 8 and 128 input tokens"
    normalized = rsi_plan.validate(plan)
    assert normalized["test_description"].startswith("Run vLLM")
    assert normalized["test_command"] is None


def test_test_command_is_direct_argv_and_renders():
    plan = base_plan()
    del plan["test_script"]
    plan["test_command"] = ["vllm", "bench", "serve", "--model", "/models/foo",
                            "--num-prompts", "128"]
    normalized = rsi_plan.validate(plan)
    assert normalized["test_command"][0:2] == ["vllm", "bench"]
    rendered = rsi_plan.render(normalized)
    payload = json.loads(rendered["steps"][0]["arguments"]["content"])
    assert payload["test_command"][-1] == "128"


def test_test_command_accepts_shell_free_string_and_rejects_shell_syntax():
    plan = base_plan()
    del plan["test_script"]
    plan["test_command"] = "vllm bench serve --model /models/foo"
    normalized = rsi_plan.validate(plan)
    assert normalized["test_command"][:2] == ["vllm", "bench"]
    plan["test_command"] += "; rm -rf /"
    with pytest.raises(rsi_plan.PlanError, match="shell-free"):
        rsi_plan.validate(plan)


def test_render_quotes_remote_root_for_shell_redirection():
    plan = base_plan()
    plan["rsi_root"] = "/home/user/RSI with space and 'quote'"
    rendered = rsi_plan.render(plan)
    command = rendered["steps"][1]["arguments"]["cmd"]
    assert shlex.quote(plan["rsi_root"]) in command
    assert "RSI with space" not in command.replace(shlex.quote(plan["rsi_root"]), "")


def test_cli_render_is_machine_readable(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(base_plan()), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPTS / "rsi_plan.py"), "render", str(path)],
                            check=True, capture_output=True, text=True)
    body = json.loads(result.stdout)
    assert body["status"] == "valid"
    assert body["plan"]["steps"][1]["tool"] == "remote_exec_command"


def test_cli_questions_returns_defaults_and_followups(tmp_path):
    path = tmp_path / "plan.json"
    value = base_plan()
    value["payload"] = {"optimization_request": "优化投机解码"}
    path.write_text(json.dumps(value), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPTS / "rsi_plan.py"), "questions", str(path)],
                            check=True, capture_output=True, text=True)
    body = json.loads(result.stdout)
    assert body["status"] == "needs_input"
    fields = {item["field"] for item in body["questions"]}
    assert fields == {"speculative_method", "speculative_weights"}
    assert body["defaults"]["profile_binding"]["tool"] == "msprof"
    assert body["defaults"]["performance_policy"] == "default"
    assert body["defaults"]["accuracy_policy"] == "default"
    assert body["defaults"]["optimization_scope"]["strategy"] == "trend_bound"

def plan(tmp_path, *, candidates=None):
    return {
        "schema": rsi_plan.SCHEMA,
        "task_id": "autotune-test",
        "endpoint": {"host": "npu.example", "port": 22},
        "source_root": "/workspace/source",
        "startup_script": "/workspace/source/start.sh",
        "test_script": "/workspace/source/benchmark.sh",
        # The plan schema intentionally accepts remote POSIX paths only;
        # pytest's local Windows temp directory is used solely for state.
        "rsi_root": "/workspace/rsi",
        "baseline": "baseline-control",
        "objective": "verified throughput",
        "operations": ["prepare", "build", "accuracy", "performance", "cleanup"],
        "parallel_workers": 2,
        "devices": ["0", "1"],
        "payload": {"candidates": candidates or [
            {"candidate_id": "c1", "method": "config", "config": {"k": 1}}
        ]},
    }


class ScriptedRunner:
    def __init__(self, *, speedup=1.2, fail=False, unknown=False, observations=None):
        self.calls = []
        self.speedup = speedup
        self.fail = fail
        self.unknown = unknown
        self.observations = observations

    def run(self, operation, payload):
        self.calls.append(operation)
        if operation == "build" and self.fail:
            return rsi_autotune.ActionReceipt(operation, {"status": "failed"})
        if operation == "performance" and self.unknown:
            return rsi_autotune.ActionReceipt(operation, {"status": "running"})
        if operation == "accuracy":
            return rsi_autotune.ActionReceipt(operation, {
                "status": "completed", "passed": True, "correctness_passed": True,
                "teacher_forced": True,
            })
        if operation == "performance":
            result = {
                "status": "completed", "passed": True,
                "benchmark_passed": True,
                "repeats": 3,
                "paired_speedup_ci_lower_bound": self.speedup,
            }
            if self.observations is not None:
                result["observations"] = self.observations
            return rsi_autotune.ActionReceipt(operation, result)
        return rsi_autotune.ActionReceipt(operation, {"status": "completed"})


def test_expand_candidates_is_deterministic_and_bounded():
    payload = {"candidate_method": "tree", "candidate_space": {"k": [1, 2], "depth": [4, 8]}}
    first = rsi_autotune.expand_candidates(payload)
    second = rsi_autotune.expand_candidates(payload)
    assert [x["candidate_id"] for x in first] == [x["candidate_id"] for x in second]
    assert len(first) == 4


def test_successful_candidate_is_promoted_only_after_all_gates(tmp_path):
    runner = ScriptedRunner()
    controller = rsi_autotune.AutotuneController(
        plan(tmp_path), runner, tmp_path / "state", workers=1,
        required_gates=rsi_autotune.DEFAULT_REQUIRED_GATES,
    )
    result = controller.run_once()
    assert result["best"]["candidate_id"] == "c1"
    assert json.loads((tmp_path / "state" / "active-best.json").read_text())["candidate_id"] == "c1"
    assert runner.calls == ["prepare", "build", "accuracy", "performance"]


def test_autotune_reuses_ledger_gates_and_records_when_source_digest_is_available(tmp_path):
    candidate_plan = plan(tmp_path)
    candidate_plan["payload"].update({
        "source_digest": "candidate-source",
        "baseline_source_digest": "baseline-source",
        "ledger_path": str(tmp_path / "experiment-ledger.jsonl"),
    })
    runner = ScriptedRunner()
    controller = rsi_autotune.AutotuneController(candidate_plan, runner, tmp_path / "state")
    result = controller.run_once()
    candidate = result["results"]["c1"]
    assert candidate["ledger_gates"]["verdict"] == "supported"
    assert candidate["gates"]["ledger_recorded"] is True
    ledger = json.loads((tmp_path / "experiment-ledger.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert ledger["task_id"] == "autotune-test"
    assert ledger["source_digest"] == "candidate-source"


def test_autotune_calls_existing_trend_bound_helper(tmp_path):
    runner = ScriptedRunner(observations=[
        {"num_speculative_tokens": 2, "throughput_tokens_s": 100},
        {"num_speculative_tokens": 4, "throughput_tokens_s": 115},
        {"num_speculative_tokens": 8, "throughput_tokens_s": 130},
    ])
    result = rsi_autotune.AutotuneController(plan(tmp_path), runner, tmp_path / "state").run_once()
    assert result["results"]["c1"]["trend_bound"]["samples"] == 3


def test_failed_candidate_is_cleaned_and_does_not_replace_baseline(tmp_path):
    runner = ScriptedRunner(fail=True)
    controller = rsi_autotune.AutotuneController(plan(tmp_path), runner, tmp_path / "state")
    result = controller.run_once()
    assert result["best"]["candidate_id"] == "baseline-control"
    assert runner.calls[-1] == "cleanup"


def test_unknown_receipt_stops_promotion_without_retry(tmp_path):
    runner = ScriptedRunner(unknown=True)
    controller = rsi_autotune.AutotuneController(plan(tmp_path), runner, tmp_path / "state")
    result = controller.run_once()
    assert result["state"] == "needs_reconcile"
    assert result["best"]["candidate_id"] == "baseline-control"
    assert runner.calls == ["prepare", "build", "accuracy", "performance"]


def test_reconcile_state_blocks_later_candidates_after_unknown(tmp_path):
    candidates = [
        {"candidate_id": "c1", "method": "config", "config": {"k": 1}},
        {"candidate_id": "c2", "method": "config", "config": {"k": 2}},
    ]
    runner = ScriptedRunner(unknown=True)
    controller = rsi_autotune.AutotuneController(
        plan(tmp_path, candidates=candidates), runner, tmp_path / "state", workers=1
    )
    first = controller.run_once()
    assert first["state"] == "needs_reconcile"
    calls = list(runner.calls)
    second = controller.run_once()
    assert second["status"] == "needs_reconcile"
    assert runner.calls == calls


def test_cli_dry_run_is_machine_readable(tmp_path, capsys):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan(tmp_path)), encoding="utf-8")
    assert rsi_autotune.main([str(path), "--dry-run", "--once", "--state-dir", str(tmp_path / "state")]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "completed"
    assert body["best"]["candidate_id"] == "baseline-control"


def test_cli_requests_missing_startup_or_test_artifacts(tmp_path, capsys):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan(tmp_path)), encoding="utf-8")
    assert rsi_autotune.main([str(path), "--state-dir", str(tmp_path / "state")]) == 2
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "needs_input"
    assert "startup_script" in body["required_inputs"][0]


def test_cli_stops_when_target_is_reached_by_default(tmp_path, monkeypatch, capsys):
    class FakeController:
        calls = 0

        def __init__(self, *args, **kwargs):
            pass

        def run_once(self):
            type(self).calls += 1
            return {"status": "completed", "best": {
                "candidate_id": f"c{type(self).calls}", "speedup": 1.07}}

    monkeypatch.setattr(rsi_autotune, "AutotuneController", FakeController)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan(tmp_path)), encoding="utf-8")
    assert rsi_autotune.main([
        str(path), "--dry-run", "--target-speedup", "1.07",
        "--state-dir", str(tmp_path / "state"),
    ]) == 0
    assert FakeController.calls == 1
    assert json.loads(capsys.readouterr().out)["best"]["speedup"] == 1.07


def test_cli_explicit_round_budget_keeps_running_after_target(tmp_path, monkeypatch, capsys):
    class FakeController:
        calls = 0

        def __init__(self, *args, **kwargs):
            pass

        def run_once(self):
            type(self).calls += 1
            return {"status": "completed", "best": {
                "candidate_id": f"c{type(self).calls}", "speedup": 1.07}}

    monkeypatch.setattr(rsi_autotune, "AutotuneController", FakeController)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan(tmp_path)), encoding="utf-8")
    assert rsi_autotune.main([
        str(path), "--dry-run", "--target-speedup", "1.07", "--max-rounds", "3",
        "--state-dir", str(tmp_path / "state"),
    ]) == 0
    assert FakeController.calls == 3
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["best"]["candidate_id"] == "c3"

def test_default_profile_and_scope_are_explicit():
    defaults = rsi_defaults.default_settings({})
    assert defaults["profile_binding"]["tool"] == "msprof"
    assert defaults["optimization_scope"]["parameters"]["num_speculative_tokens"] == "adaptive"
    assert defaults["optimization_scope"]["strategy"] == "trend_bound"


def test_defaults_do_not_produce_questions():
    assert rsi_defaults.questions({}) == []


def test_default_settings_fill_policy_values():
    defaults = rsi_defaults.default_settings({})
    assert defaults["performance_policy"] == "default"
    assert defaults["accuracy_policy"] == "default"
    assert defaults["runtime_parameter_policy"] == "discover_from_startup"
    assert defaults["startup_feature_policy"] == "allow_existing_features"
    assert defaults["source_change_policy"] == "parameters_only"
    assert defaults["algorithm_exploration_policy"] == "disabled"
    assert defaults["algorithm_exploration_authorized"] is False
    assert defaults["candidate_order"] == ["runtime_parameters", "startup_features"]


def test_speculative_request_asks_for_method_and_weights():
    items = rsi_defaults.questions({"optimization_request": "优化投机解码"})
    fields = {item["field"] for item in items}
    assert {"speculative_method", "speculative_weights"} <= fields
    choices = next(item["choices"] for item in items if item["field"] == "speculative_method")
    assert "dflash2" not in choices


def test_dflash2_alias_uses_the_dflash_runtime_method():
    plan = base_plan()
    plan["payload"] = {"speculative_method": "dflash2"}
    normalized = rsi_plan.validate(plan)
    assert normalized["payload"]["speculative_method"] == "dflash"
    assert rsi_defaults.normalize_speculative_method("dflash-2") == "dflash"


def test_selected_method_and_weights_remove_followup_questions():
    items = rsi_defaults.questions({
        "optimization_request": "优化 dflash",
        "speculative_method": "dflash",
        "speculative_weights": "/models/dflash",
    })
    fields = {item["field"] for item in items}
    assert "speculative_method" not in fields
    assert "speculative_weights" not in fields

def test_install_creates_standard_wrapper_and_detects_nonstandard_runtime(tmp_path):
    runtime = tmp_path / "rsi-mindie/bin/mindie_agent_rsi_entry.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text(
        "import json, sys\n"
        "print(json.dumps({'status': 'completed', 'operation': sys.argv[1]}))\n",
        encoding="utf-8",
    )
    result = rsi_install.install(tmp_path)
    assert result["entry_created"] is True
    assert result["runtime_entry_detected"] == "rsi-mindie/bin/mindie_agent_rsi_entry.py"
    wrapper = tmp_path / "bin/mindie_agent_rsi_entry.py"
    adapter = tmp_path / "bin/rsi_runtime_adapter.py"
    bindings = tmp_path / "config/live-runtime-bindings.json"
    assert wrapper.is_file()
    assert adapter.is_file()
    assert bindings.is_file()
    assert (tmp_path / "bin/mindie_rsi/rsi_workload.py").is_file()
    assert result["core_files_created"] > 0

    config = json.loads(bindings.read_text(encoding="utf-8"))
    config["default"]["runtime_python"] = sys.executable
    bindings.write_text(json.dumps(config), encoding="utf-8")
    process = subprocess.run(
        [sys.executable, str(wrapper), "performance", "--root", str(tmp_path)],
        input="{}",
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "RSI_BINDINGS": str(bindings)},
    )
    assert process.returncode == 0
    assert json.loads(process.stdout)["operation"] == "performance"


def test_install_falls_back_to_reference_adapter_when_runtime_is_absent(tmp_path):
    result = rsi_install.install(tmp_path)
    config = json.loads((tmp_path / "config/live-runtime-bindings.json").read_text(encoding="utf-8"))
    assert result["adapter_created"] is True
    assert config["default"]["runtime_entry"] == "bin/rsi_runtime_adapter.py"
    assert config["default"]["commands"] == {}
    assert config["default"]["profile_binding"]["tool"] == "msprof"

    process = subprocess.run(
        [sys.executable, str(tmp_path / "bin/mindie_agent_rsi_entry.py"),
         "prepare", "--root", str(tmp_path)],
        input=json.dumps({"candidate": {"candidate_id": "c1"}}),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "RSI_BINDINGS": str(tmp_path / "config/live-runtime-bindings.json")},
    )
    assert process.returncode == 0
    assert json.loads(process.stdout)["status"] == "prepared"


def test_install_preserves_existing_standard_wrapper(tmp_path):
    wrapper = tmp_path / "bin/mindie_agent_rsi_entry.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("sentinel\n", encoding="utf-8")
    result = rsi_install.install(tmp_path)
    assert result["entry_created"] is False
    assert wrapper.read_text(encoding="utf-8") == "sentinel\n"

def test_reference_adapter_never_uses_shell_and_parses_json(tmp_path):
    command = tmp_path / "command.py"
    command.write_text(
        "import json,sys\n"
        "payload=json.load(sys.stdin)\n"
        "print('diagnostic line')\n"
        "print(json.dumps({'status':'completed','passed':True,'benchmark_passed':True,\n"
        "'paired_speedup_ci_lower_bound':1.2,'request_count':4}))\n",
        encoding="utf-8",
    )
    payload = {
        "runtime_binding": {"commands": {"benchmark_cmd": [sys.executable, str(command)]}},
        "candidate": {"candidate_id": "c1"},
    }
    result = rsi_runtime_adapter.dispatch("performance", tmp_path, payload)
    assert result["passed"] is True
    assert result["paired_speedup_ci_lower_bound"] == 1.2


def test_plan_test_command_is_used_as_performance_argv(tmp_path):
    command = tmp_path / "command.py"
    command.write_text("import json; print(json.dumps({'status':'completed','passed':True}))\n",
                       encoding="utf-8")
    result = rsi_runtime_adapter.dispatch(
        "performance", tmp_path,
        {"test_command": [sys.executable, str(command)]},
    )
    assert result["passed"] is True


def test_reference_adapter_missing_evidence_fails_closed(tmp_path):
    result = rsi_runtime_adapter.dispatch("accuracy", tmp_path, {})
    assert result["status"] == "unavailable"
    assert result["passed"] is False
    assert result["reason"] == "accuracy_command_not_configured"


def test_simulation_receipt_normalizes_metrics_and_keeps_analytical_evidence(tmp_path):
    command = tmp_path / "simulator.py"
    command.write_text(
        "import json\n"
        "print(json.dumps({'status': 'completed', 'throughput': 120, 'ttft_ms': 8, 'oom': False}))\n",
        encoding="utf-8",
    )
    result = rsi_runtime_adapter.dispatch(
        "simulation", tmp_path,
        {"objective": "maximize throughput",
         "runtime_binding": {"commands": {"simulation_cmd": [sys.executable, str(command)]}}},
    )
    assert result["evidence_kind"] == "analytical"
    assert result["eligible_for_measurement"] is True
    assert result["metrics"]["throughput_tokens_s"] == 120
    assert result["simulation_score"] == 120


def test_simulation_adapter_reads_standard_output_artifacts(tmp_path):
    output = tmp_path / "sim-output"
    output.mkdir()
    (output / "predict_dict.json").write_text(
        json.dumps({"decode": {"throughput_tokens_s": 88}}), encoding="utf-8"
    )
    (output / "memory_dict.json").write_text(
        json.dumps({"rank_0": {"oom": True}}), encoding="utf-8"
    )
    command = tmp_path / "silent_simulator.py"
    command.write_text("print('simulation complete')\n", encoding="utf-8")
    result = rsi_runtime_adapter.dispatch(
        "simulation", tmp_path,
        {"objective": "maximize throughput", "simulation_output_dir": str(output),
         "runtime_binding": {"commands": {"simulation_cmd": [sys.executable, str(command)]}}},
    )
    assert result["metrics"]["throughput_tokens_s"] == 88
    assert result["oom"] is True
    assert result["eligible_for_measurement"] is False


def test_simulation_rank_prefers_higher_throughput():
    ranked = rsi_simulation.rank({
        "slow": {"eligible_for_measurement": True, "simulation_score": 10},
        "fast": {"eligible_for_measurement": True, "simulation_score": 20},
        "oom": {"eligible_for_measurement": False, "simulation_score": 100},
    }, 1)
    assert ranked == ["fast"]


def test_simulation_round_filters_candidates_before_measurement(tmp_path):
    candidates = [
        {"candidate_id": "slow", "method": "config", "config": {"k": 1}},
        {"candidate_id": "fast", "method": "config", "config": {"k": 2}},
    ]
    candidate_plan = plan(tmp_path, candidates=candidates)
    candidate_plan["operations"] = ["simulation", "prepare", "build", "accuracy", "performance", "cleanup"]
    candidate_plan["payload"].update({"simulation_top_k": 1})

    class SimulatorRunner(ScriptedRunner):
        def run(self, operation, payload):
            self.calls.append(operation)
            if operation == "simulation":
                candidate = payload["candidate"]["candidate_id"]
                return rsi_autotune.ActionReceipt(operation, {
                    "status": "completed", "passed": True,
                    "evidence_kind": "analytical", "eligible_for_measurement": True,
                    "simulation_score": 20 if candidate == "fast" else 10,
                    "metrics": {"throughput_tokens_s": 20 if candidate == "fast" else 10},
                })
            return super().run(operation, payload)

    runner = SimulatorRunner()
    controller = rsi_autotune.AutotuneController(
        candidate_plan, runner, tmp_path / "state", workers=2,
        required_gates=rsi_autotune.DEFAULT_REQUIRED_GATES,
    )
    first = controller.run_once()
    assert first["status"] == "simulation_completed"
    assert first["selected_for_measurement"] == ["fast"]
    second = controller.run_once()
    assert second["best"]["candidate_id"] == "fast"
    assert [call for call in runner.calls if call == "simulation"] == ["simulation", "simulation"]


def test_simulation_infrastructure_failure_does_not_discard_candidates(tmp_path):
    candidate_plan = plan(tmp_path)
    candidate_plan["operations"] = ["simulation", "performance"]

    class FailedSimulator:
        def run(self, operation, payload):
            return rsi_autotune.ActionReceipt(operation, {
                "status": "failed", "passed": False, "reason": "simulator_unavailable"
            })

    controller = rsi_autotune.AutotuneController(
        candidate_plan, FailedSimulator(), tmp_path / "state", workers=1,
        required_gates=(),
    )
    result = controller.run_once()
    assert result["status"] == "simulation_failed"
    queue = json.loads((tmp_path / "state" / "autotune-queue.json").read_text())
    assert queue["candidates"][0]["status"] == "pending"


def test_simulation_only_persists_global_ranking_without_measurement(tmp_path):
    candidate_plan = plan(tmp_path)
    candidate_plan["startup_script"] = None
    candidate_plan["test_script"] = None
    candidate_plan["operations"] = ["simulation"]
    candidate_plan["parallel_workers"] = 2
    candidate_plan["payload"] = {
        "candidate_method": "tree",
        "candidate_space": {"k": [1, 2, 3, 4]},
        "simulation_max_candidates": 2,
        "simulation_top_k": 2,
    }

    class SimulationOnlyRunner:
        def __init__(self):
            self.calls = []

        def run(self, operation, payload):
            self.calls.append(operation)
            candidate = payload["candidate"]
            score = candidate["config"]["k"]
            return rsi_autotune.ActionReceipt(operation, {
                "status": "completed", "passed": True,
                "evidence_kind": "analytical", "eligible_for_measurement": True,
                "simulation_score": score,
                "metrics": {"throughput_tokens_s": score},
            })

    runner = SimulationOnlyRunner()
    controller = rsi_autotune.AutotuneController(
        candidate_plan, runner, tmp_path / "state", workers=2, required_gates=(),
    )
    first = controller.run_once()
    second = controller.run_once()

    assert first["status"] == "simulation_progress"
    assert second["status"] == "simulation_completed"
    assert second["simulation_only"] is True
    assert second["selected_for_measurement"] == []
    assert len(second["ranking"]) == 4
    assert len(runner.calls) == 4
    result_path = tmp_path / "state" / "simulation-results.json"
    persisted = json.loads(result_path.read_text())
    assert persisted["schema"] == "mindie-agent/rsi-simulation-results/v1"
    assert persisted["selected_candidate_ids"] == [
        rsi_autotune.candidate_id("tree", {"k": 4}),
        rsi_autotune.candidate_id("tree", {"k": 3}),
    ]
    state = json.loads((tmp_path / "state" / "autotune-state.json").read_text())
    assert state["simulation_result_path"] == str(result_path)
    assert not (tmp_path / "state" / "active-best.json").exists()


def test_cli_stops_after_simulation_only_completion(tmp_path, monkeypatch, capsys):
    candidate_plan = plan(tmp_path)
    candidate_plan["startup_script"] = None
    candidate_plan["test_script"] = None
    candidate_plan["operations"] = ["simulation"]
    candidate_plan["payload"] = {"candidate_space": {"k": [1, 2]}}
    path = tmp_path / "simulation-plan.json"
    path.write_text(json.dumps(candidate_plan), encoding="utf-8")

    class FakeController:
        calls = 0

        def __init__(self, *args, **kwargs):
            pass

        def run_once(self):
            type(self).calls += 1
            return {"status": "simulation_completed", "simulation_only": True,
                    "selected_candidates": ["candidate-1"]}

    monkeypatch.setattr(rsi_autotune, "AutotuneController", FakeController)
    assert rsi_autotune.main([
        str(path), "--dry-run", "--state-dir", str(tmp_path / "state"),
    ]) == 0
    assert FakeController.calls == 1
    assert json.loads(capsys.readouterr().out)["simulation_only"] is True


def test_reference_adapter_wrapper_round_trip(tmp_path):
    root = tmp_path
    rsi_install.install(root)
    bindings = root / "config/live-runtime-bindings.json"
    config = json.loads(bindings.read_text(encoding="utf-8"))
    config["default"]["runtime_python"] = sys.executable
    bindings.write_text(json.dumps(config), encoding="utf-8")
    process = subprocess.run(
        [sys.executable, str(root / "bin/mindie_agent_rsi_entry.py"), "prepare", "--root", str(root)],
        input=json.dumps({"candidate": {"candidate_id": "c1"}}),
        text=True, capture_output=True, check=False,
    )
    assert process.returncode == 0
    result = json.loads(process.stdout)
    assert result["candidate_id"] == "c1"
    receipt_path = Path(result["receipt"])
    assert json.loads(receipt_path.read_text(encoding="utf-8"))["operation"] == "prepare"


def test_runtime_entry_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("print('{}')\n", encoding="utf-8")
    root = tmp_path / "rsi"
    root.mkdir()
    link = root / "entry.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    bindings = root / "bindings.json"
    bindings.write_text(json.dumps({"default": {"runtime_entry": "entry.py"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="escape"):
        # The public wrapper exercises the same path validation as installed hosts.
        rsi_entry.dispatch("prepare", root, str(bindings), {"candidate": {"candidate_id": "c1"}})


def test_cost_model_scales_millisecond_stage_fields():
    observation = rsi_cost_model.Observation.from_mapping({
        "elapsed_s": 1.0,
        "completion_tokens": 10,
        "draft_ms": 100,
        "verify_ms": 250,
    })
    assert observation.draft_s == pytest.approx(0.1)
    assert observation.verify_s == pytest.approx(0.25)


def test_unpaired_samples_and_nonpositive_speedups_fail_closed():
    receipt = {
        "baseline_samples": [{"elapsed_s": 1.0}, {"elapsed_s": 1.0}],
        "candidate_samples": [{"elapsed_s": 0.5}],
    }
    assert rsi_evidence.validate_paired(receipt, min_runs=1)["passed"] is False
    assert rsi_compare.compare(receipt, "maximize throughput")["ci_lower_ratio"] is None
    assert rsi_evidence.validate_paired({"paired_runs": [{"speedup": 0}]}, min_runs=1)["passed"] is False

def test_origin_is_discovered_from_startup_script():
    assert discover_startup_parameter("vllm --num-speculative-tokens 7") == 7
    assert discover_startup_parameter('{"num_speculative_tokens": 9}') == 9


def test_trend_uses_default_origin_when_no_observation_is_available():
    result = rsi_trend.assess_bound([])
    assert result["origin"] == 5
    assert result["next_values"] == [3, 7]


def test_trend_bound_detects_compute_saturation():
    result = rsi_trend.assess_bound([
        {"num_speculative_tokens": 2, "throughput_tokens_s": 100, "compute_utilization": 92},
        {"num_speculative_tokens": 4, "throughput_tokens_s": 100.5, "compute_utilization": 94},
        {"num_speculative_tokens": 8, "throughput_tokens_s": 100.2, "compute_utilization": 95},
    ])
    assert result["bound"] is True
    assert result["reason"] in {"compute_bound_upward", "throughput_plateau"}


def test_trend_bound_keeps_expanding_when_improving():
    result = rsi_trend.assess_bound([
        {"num_speculative_tokens": 2, "throughput_tokens_s": 100},
        {"num_speculative_tokens": 4, "throughput_tokens_s": 115},
        {"num_speculative_tokens": 8, "throughput_tokens_s": 130},
    ])
    assert result["status"] == "expand"
    assert result["next_action"] == "probe_adjacent_by_two"


def test_higher_k_loss_with_high_compute_stops_upward_branch():
    result = rsi_trend.assess_bound([
        {"num_speculative_tokens": 5, "throughput_tokens_s": 105, "pipe_utilization": 80},
        {"num_speculative_tokens": 7, "throughput_tokens_s": 100, "pipe_utilization": 95},
        {"num_speculative_tokens": 9, "throughput_tokens_s": 96, "pipe_utilization": 95},
    ], origin=7)
    assert result["direction_up"] == "stop"
    assert 11 not in result["next_values"]


def test_downward_improvement_reaches_zero_only_at_smallest_positive_k():
    result = rsi_trend.assess_bound([
        {"num_speculative_tokens": 1, "throughput_tokens_s": 120},
        {"num_speculative_tokens": 3, "throughput_tokens_s": 110},
        {"num_speculative_tokens": 7, "throughput_tokens_s": 100},
    ], origin=7)
    assert result["test_zero"] is True
    assert 0 in result["next_values"]
