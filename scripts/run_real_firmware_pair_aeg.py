#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.pair_eval import PairSpec, load_pairs_manifest  # noqa: E402


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_check_module() -> ModuleType:
    script_path = Path(__file__).resolve().with_name("check_real_firmware_pair_aeg.py")
    spec = importlib.util.spec_from_file_location("check_real_firmware_pair_aeg", script_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError("scripts/check_real_firmware_pair_aeg.py is required")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _find_pair(pairs: list[PairSpec], pair_id: str) -> PairSpec:
    for pair in pairs:
        if pair.pair_id == pair_id:
            return pair
    raise ValueError(f"pair_id not found in manifest: {pair_id}")


def _wall_timeout(time_budget_s: int) -> int:
    return max(300, int(time_budget_s) + 900)


def _guess_run_dir(stdout_text: str) -> str:
    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    for line in reversed(lines):
        if "aiedge-runs/" not in line:
            continue
        for token in reversed(line.split()):
            if "aiedge-runs/" in token:
                return token.strip().rstrip(",.;:")
    return lines[-1] if lines and lines[-1].startswith("aiedge-runs/") else ""


def _link_latest(side_root: Path, run_dir: str) -> None:
    if not run_dir:
        return
    link = side_root / "latest"
    if link.exists() or link.is_symlink():
        link.unlink()
    try:
        link.symlink_to(Path(run_dir).resolve())
    except OSError:
        pass


def _run_fetch(pair_id: str, pairs_path: Path, *, force: bool) -> dict[str, Any]:
    cmd = [sys.executable, "scripts/fetch_pair_firmware.py", "--pairs", str(pairs_path), "--pair-id", pair_id]
    if force:
        cmd.append("--force")
    started_at = time.time()
    proc = subprocess.run(
        cmd,
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "cmd": cmd,
        "returncode": int(proc.returncode),
        "duration_s": round(time.time() - started_at, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _run_analyze(
    *,
    pair: PairSpec,
    side: str,
    firmware_path: str,
    results_root: Path,
    profile: str,
    driver: str,
    time_budget_s: int,
    no_llm: bool,
    quiet: bool,
    dry_run: bool,
) -> dict[str, Any]:
    side_root = results_root / "runs" / pair.pair_id / side
    side_root.mkdir(parents=True, exist_ok=True)
    cmd = [
        "./scout",
        "analyze",
        firmware_path,
        "--ack-authorization",
        "--profile",
        profile,
        "--time-budget-s",
        str(time_budget_s),
    ]
    if no_llm:
        cmd.append("--no-llm")
    if quiet:
        cmd.append("--quiet")
    started = {
        "pair_id": pair.pair_id,
        "side": side,
        "firmware_path": firmware_path,
        "cmd": cmd,
        "driver": driver,
        "profile": profile,
        "no_llm": bool(no_llm),
        "quiet": bool(quiet),
        "started_at": time.time(),
        "wall_timeout_s": _wall_timeout(time_budget_s),
        "dry_run": bool(dry_run),
    }
    _write_json(side_root / "started.json", started)
    if dry_run:
        result = {
            **{k: started[k] for k in ["pair_id", "side", "firmware_path", "cmd", "driver", "profile", "no_llm", "quiet", "wall_timeout_s", "dry_run"]},
            "returncode": None,
            "duration_s": 0.0,
            "run_dir": "",
            "status": "dry_run",
            "timed_out": False,
        }
        _write_json(side_root / "last_run.json", result)
        return result

    env = os.environ.copy()
    env["AIEDGE_LLM_DRIVER"] = driver
    stdout_path = side_root / "stdout.txt"
    stderr_path = side_root / "stderr.txt"
    started_at = time.time()
    timed_out = False
    returncode = 20
    status = "fatal"
    try:
        with stdout_path.open("wb") as stdout_fh, stderr_path.open("wb") as stderr_fh:
            proc = subprocess.run(
                cmd,
                cwd=_REPO_ROOT,
                env=env,
                stdout=stdout_fh,
                stderr=stderr_fh,
                timeout=_wall_timeout(time_budget_s),
                check=False,
            )
        returncode = int(proc.returncode)
        status = "success" if returncode == 0 else ("partial" if returncode == 10 else "fatal")
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
        status = "fatal"
    try:
        stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        stdout_text = ""
    run_dir = _guess_run_dir(stdout_text)
    result = {
        "pair_id": pair.pair_id,
        "side": side,
        "firmware_path": firmware_path,
        "cmd": cmd,
        "driver": driver,
        "profile": profile,
        "no_llm": bool(no_llm),
        "quiet": bool(quiet),
        "returncode": returncode,
        "duration_s": round(time.time() - started_at, 3),
        "run_dir": run_dir,
        "status": status,
        "timed_out": timed_out,
        "wall_timeout_s": _wall_timeout(time_budget_s),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    _write_json(side_root / "last_run.json", result)
    _link_latest(side_root, run_dir)
    return result


def _record_reused_run(
    *,
    pair: PairSpec,
    side: str,
    firmware_path: str,
    run_dir: Path,
    results_root: Path,
) -> dict[str, Any]:
    side_root = results_root / "runs" / pair.pair_id / side
    side_root.mkdir(parents=True, exist_ok=True)
    result = {
        "pair_id": pair.pair_id,
        "side": side,
        "firmware_path": firmware_path,
        "run_dir": str(run_dir),
        "status": "reused",
        "returncode": None,
        "duration_s": 0.0,
        "timed_out": False,
    }
    _write_json(side_root / "last_run.json", result)
    _link_latest(side_root, str(run_dir))
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run or reuse an official known-vulnerable/patched firmware pair, then "
            "emit the fail-closed real_firmware_pair AEG promotion report."
        )
    )
    parser.add_argument("--pairs", type=Path, default=Path("benchmarks/pair-eval/pairs.json"))
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--results-dir", type=Path, default=Path("benchmark-results/aeg-real-pair"))
    parser.add_argument("--profile", default="exploit")
    parser.add_argument("--driver", default="codex")
    parser.add_argument("--time-budget-s", type=int, default=1800)
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--quiet", action="store_true", default=True)
    parser.add_argument("--no-quiet", dest="quiet", action="store_false")
    parser.add_argument("--fetch", action="store_true", help="Fetch or verify the selected pair before analysis.")
    parser.add_argument("--force-fetch", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Write intended commands without running scout.")
    parser.add_argument("--skip-analyze", action="store_true", help="Only evaluate existing/discovered run directories.")
    parser.add_argument("--vulnerable-run-dir", type=Path, default=None)
    parser.add_argument("--control-run-dir", type=Path, default=None)
    parser.add_argument("--patched-run-dir", type=Path, default=None, help="Alias for --control-run-dir.")
    parser.add_argument("--pattern-id", default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--fpr-max", type=float, default=0.10)
    parser.add_argument("--min-runner-pass", type=int, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    results_root = args.results_dir.resolve()
    results_root.mkdir(parents=True, exist_ok=True)
    out_path = args.out or (results_root / "reports" / f"{args.pair_id}.json")
    fetch_result: dict[str, Any] | None = None
    analyze_results: list[dict[str, Any]] = []
    try:
        pairs = load_pairs_manifest(args.pairs)
        pair = _find_pair(pairs, args.pair_id)
        if args.fetch:
            fetch_result = _run_fetch(pair.pair_id, args.pairs, force=bool(args.force_fetch))
            if int(fetch_result.get("returncode", 1)) != 0:
                payload = {
                    "schema_version": "real-firmware-pair-aeg-run-v1",
                    "pair_id": pair.pair_id,
                    "verdict": "fetch_failed",
                    "promotable_real_firmware_pair": False,
                    "fetch": fetch_result,
                }
                _write_json(out_path, payload)
                print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
                return 47

        check_module = _load_check_module()
        vulnerable_run_dir = args.vulnerable_run_dir
        control_run_dir = args.control_run_dir or args.patched_run_dir

        if not args.skip_analyze:
            if vulnerable_run_dir is None:
                vuln_result = _run_analyze(
                    pair=pair,
                    side="vulnerable",
                    firmware_path=pair.vulnerable.firmware_path,
                    results_root=results_root,
                    profile=args.profile,
                    driver=args.driver,
                    time_budget_s=int(args.time_budget_s),
                    no_llm=bool(args.no_llm),
                    quiet=bool(args.quiet),
                    dry_run=bool(args.dry_run),
                )
                analyze_results.append(vuln_result)
                if vuln_result.get("run_dir"):
                    vulnerable_run_dir = Path(str(vuln_result["run_dir"]))
            else:
                analyze_results.append(
                    _record_reused_run(
                        pair=pair,
                        side="vulnerable",
                        firmware_path=pair.vulnerable.firmware_path,
                        run_dir=vulnerable_run_dir,
                        results_root=results_root,
                    )
                )

            if control_run_dir is None:
                patched_result = _run_analyze(
                    pair=pair,
                    side="patched",
                    firmware_path=pair.patched.firmware_path,
                    results_root=results_root,
                    profile=args.profile,
                    driver=args.driver,
                    time_budget_s=int(args.time_budget_s),
                    no_llm=bool(args.no_llm),
                    quiet=bool(args.quiet),
                    dry_run=bool(args.dry_run),
                )
                analyze_results.append(patched_result)
                if patched_result.get("run_dir"):
                    control_run_dir = Path(str(patched_result["run_dir"]))
            else:
                analyze_results.append(
                    _record_reused_run(
                        pair=pair,
                        side="patched",
                        firmware_path=pair.patched.firmware_path,
                        run_dir=control_run_dir,
                        results_root=results_root,
                    )
                )
        else:
            if vulnerable_run_dir is None:
                vulnerable_run_dir = check_module._resolve_discovered_run_dir(
                    results_root, pair.pair_id, "vulnerable"
                )
            if control_run_dir is None:
                control_run_dir = check_module._resolve_discovered_run_dir(
                    results_root, pair.pair_id, "patched"
                )

        pair_gate = check_module.build_pair_gate_report(
            pair=pair,
            vulnerable_run_dir=vulnerable_run_dir,
            control_run_dir=control_run_dir,
            fpr_max=float(args.fpr_max),
            min_runner_pass=int(args.min_runner_pass),
            pattern_id=args.pattern_id,
        )
        payload = {
            "schema_version": "real-firmware-pair-aeg-run-v1",
            "pair_id": pair.pair_id,
            "fetch": fetch_result,
            "analysis": analyze_results,
            "pair_gate": pair_gate,
            "promotable_real_firmware_pair": pair_gate.get("promotable_real_firmware_pair") is True,
            "verdict": pair_gate.get("verdict", "unknown"),
        }
    except Exception as exc:
        payload = {
            "schema_version": "real-firmware-pair-aeg-run-v1",
            "pair_id": args.pair_id,
            "verdict": "error",
            "promotable_real_firmware_pair": False,
            "error": str(exc),
            "fetch": fetch_result,
            "analysis": analyze_results,
        }
        _write_json(out_path, payload)
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
        return 48

    _write_json(out_path, payload)
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", end="")
    return 0 if payload.get("promotable_real_firmware_pair") is True else 32


if __name__ == "__main__":
    raise SystemExit(main())
