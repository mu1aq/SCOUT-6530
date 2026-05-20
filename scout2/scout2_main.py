import sys
import os
import json
from modules.scout2_semantic import Scout2SemanticAnalyst
from modules.scout2_taint import Scout2TaintEngine
from modules.scout2_env_check import run_preflight

def main(rootfs_path, binary_to_analyze):
    print("=== SCOUT 2.0 (Autonomous Vulnerability Verification) ===")
    
    # 1. Environment Check
    env_status = run_preflight()
    
    # 2. Semantic Analysis
    semantic_analyst = Scout2SemanticAnalyst(binary_to_analyze)
    semantic_findings = semantic_analyst.run()
    
    # 3. Taint Analysis
    taint_engine = Scout2TaintEngine(rootfs_path)
    taint_map = taint_engine.run()
    
    # 4. Report Generation
    report = {
        "environment": env_status,
        "semantic_findings": semantic_findings,
        "ipc_map": taint_map
    }
    
    with open("scout2_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("[+] SCOUT 2.0 analysis complete. Report saved to scout2_report.json")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 scout2_main.py <rootfs_path> <target_binary>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
