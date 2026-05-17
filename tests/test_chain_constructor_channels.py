from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from aiedge.chain_constructor import ChainConstructorStage, ConfigChannel, IPCChannel, WebAPIChannel
from aiedge.stage import StageContext


def _write_json(run_dir: Path, rel: str, payload: dict[str, Any]) -> None:
    path = run_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ctx(run_dir: Path) -> StageContext:
    return StageContext(run_dir=run_dir, logs_dir=run_dir / "logs", report_dir=run_dir / "report")


def test_channel_dataclasses_emit_plan_ir_metadata() -> None:
    assert WebAPIChannel(target="/api/config").as_dict()["channel_type"] == "web_api"
    assert ConfigChannel(target="interface").as_dict()["trigger"] == "config_commit_reload_daemon_parse_or_boot"
    ipc = IPCChannel(target="/tmp/scout.sock", ipc_mechanism="unix_socket").as_dict()
    assert ipc["channel_type"] == "ipc"
    assert ipc["ipc_mechanism"] == "unix_socket"


def test_chain_constructor_emits_channels_for_shared_web_api(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    web_bin = "stages/extraction/rootfs/www/cgi-bin/api.cgi"
    daemon_bin = "stages/extraction/rootfs/usr/sbin/cmxddnsd"
    _write_json(
        run_dir,
        "stages/inventory/binary_analysis.json",
        {
            "hits": [
                {
                    "path": web_bin,
                    "matched_symbols": ["/api/config", "recv", "nvram_set"],
                    "arch": "mipsel-32",
                    "hardening": {},
                },
                {
                    "path": daemon_bin,
                    "matched_symbols": ["/api/config", "popen", "nvram_get"],
                    "arch": "mipsel-32",
                    "hardening": {},
                },
            ]
        },
    )
    _write_json(
        run_dir,
        "stages/findings/exploit_candidates.json",
        {
            "candidates": [
                {
                    "candidate_id": "src:web",
                    "path": web_bin,
                    "source_api": "recv",
                    "families": ["network_io"],
                    "confidence": 0.7,
                },
                {
                    "candidate_id": "sink:daemon",
                    "path": daemon_bin,
                    "sink_symbol": "popen",
                    "families": ["cmd_exec_injection_risk"],
                    "confidence": 0.8,
                },
            ]
        },
    )

    outcome = ChainConstructorStage(no_llm=True).run(_ctx(run_dir))

    assert outcome.status == "ok"
    chains = cast(
        dict[str, Any],
        json.loads((run_dir / "stages/chain_construction/chains.json").read_text(encoding="utf-8")),
    )["chains"]
    channel_chains = [chain for chain in chains if chain.get("channels")]
    assert channel_chains
    channels = channel_chains[0]["channels"]
    assert channels[0]["channel_type"] == "web_api"
    assert channels[0]["target"] == "/api/config"


def test_chain_constructor_uses_string_hits_for_shared_config_channel(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-string-hits"
    run_dir.mkdir(parents=True)
    web_bin = "stages/extraction/rootfs/www/cgi-bin/api.cgi"
    daemon_bin = "stages/extraction/rootfs/usr/sbin/cmxddnsd"
    _write_json(
        run_dir,
        "stages/inventory/binary_analysis.json",
        {
            "hits": [
                {"path": web_bin, "matched_symbols": ["recv"], "arch": "mipsel-32", "hardening": {}},
                {"path": daemon_bin, "matched_symbols": ["popen"], "arch": "mipsel-32", "hardening": {}},
            ]
        },
    )
    _write_json(
        run_dir,
        "stages/inventory/string_hits.json",
        {
            "samples": [
                {"file": web_bin, "match": "interface"},
                {"file": daemon_bin, "match": "interface"},
            ]
        },
    )
    _write_json(
        run_dir,
        "stages/findings/exploit_candidates.json",
        {
            "candidates": [
                {"candidate_id": "src:web", "path": web_bin, "source_api": "recv", "families": ["network_io"], "confidence": 0.7},
                {"candidate_id": "sink:daemon", "path": daemon_bin, "sink_symbol": "popen", "families": ["cmd_exec_injection_risk"], "confidence": 0.8},
            ]
        },
    )

    outcome = ChainConstructorStage(no_llm=True).run(_ctx(run_dir))

    assert outcome.status == "ok"
    payload = cast(
        dict[str, Any],
        json.loads((run_dir / "stages/chain_construction/chains.json").read_text(encoding="utf-8")),
    )
    channels = [ch for chain in payload["chains"] for ch in chain.get("channels", [])]
    assert any(ch["channel_type"] == "config" and ch["target"] == "interface" for ch in channels)
