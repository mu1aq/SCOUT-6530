import os
import re
import json
from typing import List, Dict
from .stage import Stage, StageContext, StageOutcome

class ScriptAnalyzer(Stage):
    """
    Analyzes shell scripts for vulnerabilities.
    Reads the script list from inventory.json.
    """
    def __init__(self, firmware_dest):
        self.firmware_dest = firmware_dest
        self.dangerous_patterns = [
            (re.compile(r'eval\s+.*\$'), "Potentially insecure eval with variables"),
            (re.compile(r'`.*\$'), "Backtick execution with variables"),
            (re.compile(r'\$\(.*\$.*\)'), "Command substitution with variables"),
            (re.compile(r'\$\{?\w+\}?(?!")'), "Unquoted variable usage (possible injection)")
        ]

    @property
    def name(self) -> str:
        return "script_analysis"

    def run(self, ctx: StageContext) -> StageOutcome:
        inventory_path = ctx.run_dir / "stages" / "inventory" / "inventory.json"
        scripts = []
        
        if inventory_path.exists():
            try:
                with open(inventory_path, 'r') as f:
                    inventory = json.load(f)
                    scripts = inventory.get('scripts', [])
            except Exception:
                pass

        findings = []
        root_fs = ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "squashfs-root"

        for script_path in scripts:
            full_path = ctx.run_dir / script_path
            
            if not full_path.exists():
                continue
                
            try:
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for pattern, desc in self.dangerous_patterns:
                        for i, line in enumerate(content.splitlines()):
                            if pattern.search(line):
                                findings.append({
                                    "file": str(script_path),
                                    "line": i + 1,
                                    "content": line.strip(),
                                    "description": desc,
                                    "severity": "Medium" if "Unquoted" in desc else "High"
                                })
            except Exception:
                continue
        
        return StageOutcome(
            status="ok",
            details={"findings": findings, "scripts_analyzed": len(scripts)}
        )
