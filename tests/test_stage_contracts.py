from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from aiedge.run import analyze_run, create_run


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run_validator(run_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "validate_stage_outputs.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=_repo_root(),
        text=True,
        capture_output=True,
        check=False,
    )


def _create_sample_run(tmp_path: Path) -> Path:
    firmware = tmp_path / "tiny.bin"
    _ = firmware.write_bytes(b"STAGE-CONTRACT-TINY")
    info = create_run(
        str(firmware),
        case_id="stage-contracts",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=1, no_llm=True)
    return info.run_dir


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def test_validate_stage_outputs_accepts_good_sample_run(tmp_path: Path) -> None:
    run_dir = _create_sample_run(tmp_path)

    res = _run_validator(run_dir)

    assert res.returncode == 0, res.stdout + res.stderr
    assert "[OK]" in res.stdout


def test_validate_stage_outputs_fails_when_stage_manifest_has_absolute_artifact_path(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    stage_json_path = run_dir / "stages" / "tooling" / "stage.json"
    stage_json = _load_json(stage_json_path)
    artifacts = cast(list[dict[str, Any]], stage_json["artifacts"])
    artifacts[0]["path"] = "/tmp/not-run-relative.json"
    _write_json(stage_json_path, stage_json)

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "stage.json" in combined
    assert "path" in combined
    assert "tooling" in combined


def test_validate_stage_outputs_fails_when_referenced_artifact_is_missing(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    missing_artifact = run_dir / "stages" / "inventory" / "inventory.json"
    missing_artifact.unlink()

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "inventory.json" in combined
    assert "missing" in combined.lower()


def test_validate_stage_outputs_fails_when_inventory_artifact_shape_is_invalid(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    inventory_json_path = run_dir / "stages" / "inventory" / "inventory.json"
    inventory_json = _load_json(inventory_json_path)
    summary = cast(dict[str, Any], inventory_json["summary"])
    summary["files"] = "not-an-int"
    _write_json(inventory_json_path, inventory_json)

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "inventory.json" in combined
    assert "summary" in combined
    assert "files" in combined


def test_validate_stage_outputs_fails_when_poc_validation_shape_is_invalid(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    poc_validation_json_path = run_dir / "stages" / "poc_validation" / "poc_validation.json"
    poc_validation_json = _load_json(poc_validation_json_path)
    poc_validation_json["checks"] = "not-a-list"
    _write_json(poc_validation_json_path, poc_validation_json)

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "poc_validation.json" in combined
    assert "checks" in combined


def test_validate_stage_outputs_fails_when_exploit_intel_boundary_is_missing(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    exploit_intel_path = run_dir / "stages" / "exploit_intel" / "exploit_intel.json"
    exploit_intel = _load_json(exploit_intel_path)
    exploit_intel["safety_note"] = "public advisories are proof"
    _write_json(exploit_intel_path, exploit_intel)

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "exploit_intel.json" in combined
    assert "metadata-only" in combined.lower()


def test_validate_stage_outputs_fails_when_autopoc_seed_can_reuse_public_poc(
    tmp_path: Path,
) -> None:
    run_dir = _create_sample_run(tmp_path)
    seeds_path = run_dir / "stages" / "exploit_intel" / "autopoc_seeds.json"
    seeds = _load_json(seeds_path)
    seeds["candidates"] = [
        {
            "candidate_id": "external-intel:CVE-2023-1389",
            "chain_id": "external_intel_CVE_2023_1389_cmd_injection",
            "source": "exploit_intel",
            "priority": "high",
            "score": 0.86,
            "families": ["cmd_injection"],
            "summary": "metadata seed",
            "attack_hypothesis": "adapt only with firmware-local evidence",
            "expected_impact": ["cmd_injection"],
            "validation_plan": [
                "bind CVE/advisory structure to firmware-local evidence before probing"
            ],
            "evidence_refs": ["stages/cve_scan/cve_matches.json"],
            "cve_id": "CVE-2023-1389",
            "sink": "firmware-local web command sink",
            "channels": [],
            "plan_ir": {"claim_boundary": "firmware-local evidence only"},
            "external_intel_candidate_ref": "/tmp/public-poc.json",
            "forbidden_reuse": [],
        }
    ]
    _write_json(seeds_path, seeds)

    res = _run_validator(run_dir)

    assert res.returncode != 0
    combined = res.stdout + res.stderr
    assert "autopoc_seeds.json" in combined
    assert "forbidden_reuse" in combined
    assert "external_intel_candidate_ref" in combined
