import subprocess
import os
import json

def check_docker():
    try:
        subprocess.check_output(["docker", "--version"])
        return True
    except:
        return False

def check_images(required_images):
    missing = []
    for img in required_images:
        try:
            subprocess.check_output(["docker", "image", "inspect", img])
        except:
            missing.append(img)
    return missing

def run_preflight():
    print("[*] Running SCOUT 2.0 Pre-flight check...")
    report = {
        "docker_available": check_docker(),
        "missing_images": check_images(["pandawan:latest", "alpine:3.23"])
    }
    
    if not report["docker_available"]:
        print("[!] ERROR: Docker is not installed or accessible.")
    if report["missing_images"]:
        print(f"[!] WARNING: Missing required images: {', '.join(report['missing_images'])}")
    
    return report

if __name__ == "__main__":
    results = run_preflight()
    print(json.dumps(results, indent=2))
