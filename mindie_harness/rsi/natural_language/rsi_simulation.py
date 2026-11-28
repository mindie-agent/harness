#!/usr/bin/env python3
"""Normalize analytical simulator receipts for RSI candidate filtering."""
from __future__ import annotations

import math
import json
from pathlib import Path
from typing import Any, Mapping

METRIC_ALIASES = {
    "throughput_tokens_s": ("throughput_tokens_s", "throughput", "tokens_per_s"),
    "ttft_s": ("ttft_s", "ttft", "ttft_ms"),
    "tpot_s": ("tpot_s", "tpot", "decode_s_per_token", "decode_ms"),
    "prefill_s": ("prefill_s", "prefill", "prefill_ms"),
    "decode_s": ("decode_s", "decode", "decode_ms"),
    "hbm_peak_gb": ("hbm_peak_gb", "peak_hbm_gb", "memory_peak_gb", "hbm_gb"),
}


def _number(value: Any, *, milliseconds: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0:
        return None
    return result / 1000.0 if milliseconds else result


def _mapping_items(value: Any):
    if not isinstance(value, Mapping):
        return
    yield value
    for nested in value.values():
        yield from _mapping_items(nested)


def _metrics(value: Any) -> dict[str, float]:
    result: dict[str, float] = {}
    for mapping in _mapping_items(value):
        for name, aliases in METRIC_ALIASES.items():
            for key in aliases:
                if key in mapping:
                    number = _number(mapping[key], milliseconds=key.endswith("_ms"))
                    if number is not None:
                        result.setdefault(name, number)
                    break
    return result


def load_artifacts(output_dir: Any) -> dict[str, Any]:
    """Read the simulator's standard JSON files when stdout is not JSON."""
    if not isinstance(output_dir, str) or not output_dir.strip():
        return {}
    path = Path(output_dir)
    if not path.is_dir():
        return {}
    result: dict[str, Any] = {}
    for name in ("predict_dict.json", "memory_dict.json"):
        candidate = path / name
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        result[name[:-5]] = value
    return result


def score_for_objective(metrics: Mapping[str, Any], objective: str) -> float | None:
    """Convert an objective metric into a larger-is-better ranking score."""
    lowered = objective.lower()
    if any(token in lowered for token in ("ttft", "latency", "延迟")):
        value = metrics.get("ttft_s") or metrics.get("tpot_s") or metrics.get("decode_s")
        return 1.0 / float(value) if isinstance(value, (int, float)) and value > 0 else None
    value = metrics.get("throughput_tokens_s")
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    value = metrics.get("decode_s")
    return 1.0 / float(value) if isinstance(value, (int, float)) and value > 0 else None


def normalize(result: Mapping[str, Any], payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a simulator receipt with explicit analytical evidence."""
    payload = payload or {}
    artifacts = load_artifacts(
        payload.get("simulation_output_dir") or payload.get("simulation_output_path")
    )
    result = {**artifacts, **dict(result)}
    raw: dict[str, Any] = {}
    for key in ("metrics", "predict", "predict_dict", "prediction", "result"):
        value = result.get(key)
        if isinstance(value, Mapping):
            raw.update(value)
    raw.update(result)
    metrics = _metrics(raw)
    oom = bool(result.get("oom") or result.get("memory_oom") or result.get("status") == "oom")
    oom = oom or any(
        isinstance(mapping.get("oom"), bool) and mapping.get("oom")
        for mapping in _mapping_items(result)
    )
    unsupported = bool(result.get("unsupported") or result.get("unsupported_configuration"))
    passed = result.get("passed") is not False and result.get("status") not in {
        "failed", "error", "infra_failed", "unknown", "unavailable"
    }
    score = score_for_objective(metrics, str(payload.get("objective") or ""))
    normalized = dict(result)
    normalized.update({
        "status": "completed" if passed else str(result.get("status") or "failed"),
        "passed": passed,
        "evidence_kind": "analytical",
        "eligible_for_measurement": passed and not oom and not unsupported and score is not None,
        "oom": oom,
        "unsupported": unsupported,
        "metrics": metrics,
        "simulation_score": score,
        "assumptions": result.get("assumptions") or payload.get("simulation_assumptions") or {},
    })
    return normalized


def rank(receipts: Mapping[str, Mapping[str, Any]], top_k: int) -> list[str]:
    eligible = [
        (candidate_id, receipt) for candidate_id, receipt in receipts.items()
        if receipt.get("eligible_for_measurement") is True
        and isinstance(receipt.get("simulation_score"), (int, float))
    ]
    eligible.sort(key=lambda pair: float(pair[1]["simulation_score"]), reverse=True)
    return [candidate_id for candidate_id, _ in eligible[:max(1, int(top_k))]]
