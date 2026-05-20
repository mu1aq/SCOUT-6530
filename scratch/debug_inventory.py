import os

target = "/work/10-14_ACTIVE/12_build/12.02_agents/SCOUT/aiedge-runs/2026-05-20_0143_sha256-db84e89cd312/stages/extraction/_firmware.bin.extracted/squashfs-root/lib/libecs.so"
symbol = b"curl_easy_setopt"

with open(target, "rb") as f:
    content = f.read()
    if symbol in content:
        print(f"FOUND {symbol} in {target}")
    else:
        print(f"NOT FOUND {symbol} in {target}")
