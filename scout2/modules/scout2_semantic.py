import json
import subprocess
import os

class Scout2SemanticAnalyst:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.findings = []

    def extract_metadata(self):
        print(f"[*] Extracting metadata for {self.binary_path}...")
        # Get strings
        strings = subprocess.check_output(["strings", self.binary_path]).decode(errors='ignore').splitlines()
        # Get symbols
        try:
            symbols = subprocess.check_output(["nm", "-D", self.binary_path]).decode(errors='ignore').splitlines()
        except:
            symbols = []
        return {"strings": strings[:1000], "symbols": symbols} # Truncate for prompt efficiency

    def analyze_curl_usage(self):
        print("[*] Analyzing libcurl usage patterns...")
        # Check for curl_easy_setopt
        try:
            output = subprocess.check_output(["nm", "-D", self.binary_path]).decode()
            if "curl_easy_setopt" in output:
                self.findings.append({
                    "type": "logic_risk",
                    "id": "SC2-LOG-001",
                    "title": "libcurl usage detected",
                    "description": f"Binary {os.path.basename(self.binary_path)} uses curl_easy_setopt. High risk of SSL verification disablement."
                })
        except:
            pass

    def run(self):
        self.analyze_curl_usage()
        # In a real SCOUT 2.0, this would call an LLM API here with the extracted metadata
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 scout2_semantic.py <binary_path>")
        sys.exit(1)
    
    analyst = Scout2SemanticAnalyst(sys.argv[1])
    results = analyst.run()
    print(json.dumps(results, indent=2))
