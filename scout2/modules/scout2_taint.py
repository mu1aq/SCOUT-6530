import os
import subprocess
import json

class Scout2TaintEngine:
    def __init__(self, rootfs_path):
        self.rootfs_path = rootfs_path
        self.ipc_map = {}

    def scan_for_sockets(self):
        print(f"[*] Scanning {self.rootfs_path} for IPC socket patterns...")
        # Search for common socket paths in binaries
        try:
            grep_out = subprocess.check_output(
                ["grep", "-r", "/var/run/", self.rootfs_path], 
                stderr=subprocess.STDOUT
            ).decode(errors='ignore')
            
            for line in grep_out.splitlines():
                if "socket" in line or ".sock" in line or "ipc" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        binary = parts[0]
                        socket = parts[1]
                        if socket not in self.ipc_map:
                            self.ipc_map[socket] = []
                        if binary not in self.ipc_map[socket]:
                            self.ipc_map[socket].append(binary)
        except:
            pass

    def run(self):
        self.scan_for_sockets()
        return self.ipc_map

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 scout2_taint.py <rootfs_path>")
        sys.exit(1)
    
    engine = Scout2TaintEngine(sys.argv[1])
    results = engine.run()
    print(json.dumps(results, indent=2))
