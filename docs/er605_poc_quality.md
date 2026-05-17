# ER605 PoC Quality Review — Universal Chaining

Source basis: Out of Bounds' ER605 write-up, "TP-Link ER605 DDNS Pre-Auth RCE: Chaining CVE-2024-5242, CVE-2024-5243, CVE-2024-5244" (2026-02-04), plus SCOUT's `aiedge-runs/2026-05-17_1347_sha256-db84e89cd312-1` ER605 artifact.

## What the public analysis requires

The practical ER605 chain is not a flat inbound HTTP/socket bug. The write-up describes a `cmxddnsd` Comexe DDNS client chain with these properties:

1. The router periodically communicates with Comexe DDNS servers (`Dns1.comexe.net` / `.cn`) over a custom UDP protocol.
2. The attacker needs a lab WAN/MITM position, usually by controlling routing/DNS in the test network.
3. The protocol has a plaintext outer `Data` field containing an inner encrypted/custom-Base64 payload.
4. Inner fields include `OK`, `MSG`, `ErrorCode`, and `UpdateSvr1/2`, delimited by `0x01`.
5. A realistic chain is two-stage: `UpdateSvr1`-style state corruption for an info leak, then `ErrorCode` stack overflow classification/control. Dynamic RCE requires leak-derived addresses and build-specific constraints.

## Previous SCOUT PoC quality

Before this pass, SCOUT produced useful but incomplete PoC scaffolding:

- **Strengths**
  - It found config-derived command-execution candidates in ER605 artifacts.
  - It propagated `channels[]` and `plan_ir` into deterministic templates.
  - It stayed non-weaponized and lab-gated.

- **Quality gaps against the public ER605 analysis**
  - It modeled `cmxddnsd` too much like a generic config parser or direct service probe.
  - It did not represent the Comexe-specific DDNS protocol spoofing/MITM prerequisite.
  - It did not distinguish `UpdateSvr1` leak setup from `ErrorCode` control-flow classification.
  - It had no explicit quality checks for `Data`, custom Base64/DES reconstruction gaps, `0x01` delimiter constraints, or leak-before-control proof requirements.

**Quality verdict before improvement:** good triage artifact, weak exploit-specific PoC scaffold for this article. It should be treated as a lead-ranking probe, not as a reproduction-quality ER605 PoC.

## Improvements implemented

This pass adds a non-weaponized ER605/Comexe DDNS quality path:

- `exploitability_dossier.py`
  - Detects Comexe DDNS parser candidates using `cmxddnsd`, Comexe server names, `Data`, `ErrorCode`, `UpdateSvr1/2`, and parser sink markers.
  - Emits `comexe_ddns_protocol`, `ddns_response_parser`, `protocol_spoofing_required`, `info_leak_chain_candidate`, and `bounded_protocol_probe` families.
  - Emits channels for `dns_mitm`, `udp_ddns_response`, `parser_field`, and `info_leak_then_control`.
  - Enriches controllability with `0x01` delimiter and `0x00`/`0x01` bad-byte constraints.

- `exploit_state_machine.py`
  - Preserves dossier families into state-machine seeds.
  - Lowers Comexe candidates to `classify_ddns_protocol_chain_quality` Plan IR.
  - Uses protocol-aware actions such as `emulate_protocol_channel`, `stage_bounded_field_probe`, and `validate_leak_before_control_boundary`.

- `exploit_autopoc.py`
  - Avoids selecting duplicate candidate IDs from dossier and state-machine sources.
  - Synthesizes protocol-aware Plan IR when only channel metadata is present.

- `poc_templates.py`
  - Adds `comexe_ddns_protocol` deterministic template.
  - Generates a safe blueprint-only probe with short benign fields and a packet hash.
  - Does **not** implement the overlong fields, ROP layout, command execution, DES key recovery, or network spoofing server.

## Current E2E evidence

Run: `aiedge-runs/2026-05-17_1347_sha256-db84e89cd312-1`

Subset rerun:

```text
chain_construction -> exploitability_dossier -> protocol_model -> exploit_state_machine -> exploit_autopoc -> poc_validation
```

Observed:

- `exploitability_dossier`: 53 candidates, including 2 `comexe_ddns_parser_chain:cmxddnsd:*` candidates.
- Comexe candidates contain channel sequence:
  - `dns_mitm`
  - `udp_ddns_response`
  - `parser_field`
  - `info_leak_then_control`
- `exploit_state_machine`: 52 machines, Comexe machines use goal `classify_ddns_protocol_chain_quality`.
- `exploit_autopoc`: selected 5 distinct candidate IDs/chains, including 2 Comexe DDNS blueprint probes.
- Comexe evidence bundles contain 21 transition rows each (7 Plan IR transitions x 3 repro attempts).
- `poc_validation`: ok. AutoPoC remains `partial` because there is no live lab target/marker readback; this is expected and honest.

## Current quality verdict

**Quality after improvement: medium-high for safe reproduction planning, intentionally not weaponized.**

The generated Comexe PoC is now structurally aligned with the public analysis: it models MITM/DDNS response spoofing, protocol field staging, and leak-before-control boundaries. It is suitable for analyst handoff and lab harness planning.

It is still not a full exploit reproduction because SCOUT deliberately does not generate:

- overlong `UpdateSvr1` or `ErrorCode` payloads,
- ROP gadgets or command strings,
- DES/key-transform implementation sufficient for valid malicious packets,
- DHCP/DNS spoofing infrastructure,
- live leak parsing or libc-base calculation.

## Next quality upgrades

1. Add a lab harness role that emulates the Comexe server and captures router DDNS traffic in an isolated test network.
2. Add parser-only replay against an instrumented `cmxddnsd` under QEMU/GDB to upgrade blueprint transitions to observed parser evidence.
3. Recover field bounds from patched/vulnerable diffs and encode only safe boundary checks, not exploit payload bytes.
4. Add a live verifier that can mark `dns_mitm`, `udp_ddns_response`, and `info_leak_then_control` transitions as observed without crossing into weaponized payload generation.
