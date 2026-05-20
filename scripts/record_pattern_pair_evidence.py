#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from aiedge.exploit_rag import PairEvidenceError, build_pair_evidence, record_pair_evidence  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a vulnerable/control AEG pair and optionally append the resulting "
            "evidence to a curated Exploit Pattern RAG card."
        )
    )
    parser.add_argument("pattern_id", help="Curated pattern-card id under data/exploit_references/patterns/.")
    parser.add_argument(
        "--kind",
        required=True,
        choices=["synthetic_pair", "real_firmware_pair"],
        help="Evidence type to record. Release claims should use real_firmware_pair.",
    )
    parser.add_argument("--vulnerable-run-dir", type=Path, required=True)
    parser.add_argument("--control-run-dir", type=Path, required=True)
    parser.add_argument("--patterns-dir", type=Path, default=None)
    parser.add_argument("--evidence-id", default=None)
    parser.add_argument("--artifact", default=None, help="Stable manifest/report path for the pair evidence.")
    parser.add_argument("--notes", default=None)
    parser.add_argument("--vulnerable-firmware-sha256", default=None)
    parser.add_argument("--control-firmware-sha256", default=None)
    parser.add_argument("--cve", default=None)
    parser.add_argument("--target-family", default=None)
    parser.add_argument("--fpr-max", type=float, default=0.10)
    parser.add_argument("--min-runner-pass", type=int, default=1)
    parser.add_argument("--apply", action="store_true", help="Append evidence to exploit.json; default is dry-run JSON.")
    parser.add_argument("--replace", action="store_true", help="Replace existing evidence with the same evidence_id.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        evidence = build_pair_evidence(
            args.pattern_id,
            kind=args.kind,
            vulnerable_run_dir=args.vulnerable_run_dir,
            control_run_dir=args.control_run_dir,
            evidence_id=args.evidence_id,
            artifact=args.artifact,
            notes=args.notes,
            vulnerable_firmware_sha256=args.vulnerable_firmware_sha256,
            control_firmware_sha256=args.control_firmware_sha256,
            cve=args.cve,
            target_family=args.target_family,
            fpr_max=args.fpr_max,
            min_runner_pass=args.min_runner_pass,
        )
        payload: dict[str, object] = {"schema_version": "pattern-pair-evidence-record-v1", "evidence": evidence}
        if args.apply:
            card_path = record_pair_evidence(
                args.pattern_id,
                evidence,
                patterns_dir=args.patterns_dir,
                replace=args.replace,
            )
            payload["updated_card"] = str(card_path)
        print(json.dumps(payload, indent=2, sort_keys=True) + "\n", end="")
        return 0
    except PairEvidenceError as exc:
        print(json.dumps({"schema_version": "pattern-pair-evidence-record-v1", "error": str(exc)}, indent=2, sort_keys=True) + "\n", end="")
        return 46


if __name__ == "__main__":
    raise SystemExit(main())
