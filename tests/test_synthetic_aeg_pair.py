from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable, cast


def _load_pair_runner() -> Callable[[Path], dict[str, object]]:
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "run_aeg_synthetic_pair.py"
    spec = importlib.util.spec_from_file_location("run_aeg_synthetic_pair", script_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"unable to load synthetic pair script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded = cast(ModuleType, module)
    runner = getattr(loaded, "run_synthetic_pair")
    if not callable(runner):
        raise AssertionError("run_synthetic_pair is not callable")
    return cast(Callable[[Path], dict[str, object]], runner)


def _case(summary: dict[str, object], name: str) -> dict[str, object]:
    cases = cast(dict[str, object], summary["cases"])
    return cast(dict[str, object], cases[name])


def _gate(case: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], case["gate"])


def _checks(case: dict[str, object]) -> dict[str, bool]:
    return cast(dict[str, bool], _gate(case)["checks"])


def test_synthetic_aeg_pair_splits_vulnerable_from_patched_control(
    tmp_path: Path,
) -> None:
    run_synthetic_pair = _load_pair_runner()
    summary = run_synthetic_pair(tmp_path / "synthetic-pair")

    assert summary["passed"] is True

    vulnerable = _case(summary, "vulnerable")
    assert _gate(vulnerable)["passed"] is True
    assert cast(dict[str, object], vulnerable["verified_chain"])["state"] == "pass"
    assert all(_checks(vulnerable).values())

    patched = _case(summary, "patched_control")
    assert _gate(patched)["passed"] is False
    assert cast(dict[str, object], patched["verified_chain"])["state"] == "fail"
    patched_checks = _checks(patched)
    assert patched_checks["autopoc_runner_pass"] is False
    assert patched_checks["poc_validation_reproducible"] is False
    assert patched_checks["verified_chain_pass"] is False
    assert patched_checks["quality_fpr_ceiling"] is False
    assert patched_checks["no_high_severity_fp_verified"] is False

    summary_path = tmp_path / "synthetic-pair" / "synthetic_aeg_pair_summary.json"
    assert summary_path.is_file()
    persisted = cast(
        dict[str, object], json.loads(summary_path.read_text(encoding="utf-8"))
    )
    assert persisted["passed"] is True


def test_synthetic_aeg_pair_cli_reports_passed_pair(tmp_path: Path) -> None:
    work_root = tmp_path / "cli-pair"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/run_aeg_synthetic_pair.py",
            "--work-root",
            str(work_root),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    summary = cast(dict[str, object], json.loads(proc.stdout))
    assert summary["passed"] is True
    assert (work_root / "synthetic_aeg_pair_summary.json").is_file()
