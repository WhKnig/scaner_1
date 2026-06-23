#!/usr/bin/env python3
import argparse
import subprocess
import time
import os
import shutil
import string
import random
import requests
import sys

STAND_PATH = "/app/stand/microservices-demo-main"
MANIFESTS_PATH = os.path.join(STAND_PATH, "release", "kubernetes-manifests.yaml")
RESULTS_DIR = "/app/results_goo"
PROXY_PORT = 8081
FRONTEND_PORT = 8080 # we'll port-forward to this

def run_cmd(cmd, check=True, capture_output=False):
    print(f"[*] Running: {cmd}")
    return subprocess.run(
        cmd,
        shell=True,
        check=check,
        text=True,
        capture_output=capture_output
    )

def teardown():
    print("=== TEARDOWN ===")
    run_cmd(f"kubectl delete -f {MANIFESTS_PATH} --ignore-not-found=true", check=False, capture_output=True)
    # The default deploy puts it in default namespace, let's wait for pods to disappear
    time.sleep(5)
    
def deploy():
    print("=== DEPLOY ===")
    run_cmd(f"kubectl apply -f {MANIFESTS_PATH}", check=False, capture_output=True)
    
    print("[*] Patching frontend to use local vulnerable image...")
    # By default, frontend uses google-samples image. We need our locally built frontend:local.
    # To use it locally on orbstack, we patch the deployment to use frontend:local and imagePullPolicy: Never or IfNotPresent.
    patch_cmd = """kubectl set image deployment/frontend server=frontend:local"""
    run_cmd(patch_cmd, check=False)
    
    # We must also ensure imagePullPolicy allows local images if tag is not "latest"
    # Or just rely on OrbStack caching it. "frontend:local" will trigger IfNotPresent usually.
    run_cmd("kubectl rollout restart deployment frontend", check=False)

def wait_for_pods(timeout=600):
    print(f"\n[*] Waiting for ALL Online Boutique pods to be ready (timeout {timeout}s)...")
    
    # Wait for the deployments specifically first
    run_cmd(f"kubectl wait --for=condition=available --timeout={timeout}s deployment --all", check=False)
    
    # Wait for all individual pods to be ready
    result = run_cmd(f"kubectl wait --for=condition=ready pod --all --timeout={timeout}s", check=False)
    
    if result.returncode == 0:
        print("[+] All pods are Running and Ready!")
        return True
    else:
        print("[!] ERROR: Timeout waiting for ALL pods to become ready.")
        run_cmd("kubectl get pods", check=False)
        return False

def check_localhost():
    print(f"[*] Checking if localhost:{FRONTEND_PORT} is accessible...")
    for _ in range(12):
        try:
            resp = requests.get(f"http://localhost:{FRONTEND_PORT}/", timeout=5)
            if resp.status_code < 500:
                print(f"[+] localhost:{FRONTEND_PORT} is up! (Status: {resp.status_code})")
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    print(f"[!] ERROR: localhost:{FRONTEND_PORT} is not reachable.")
    return False

def main():
    parser = argparse.ArgumentParser(description="Automated Scanner Testing Stand (Online Boutique)")
    parser.add_argument("--iterations", type=int, default=10, help="Number of test iterations")
    parser.add_argument("--deploy-only", action="store_true", help="Deploy once, skip scanning, skip teardown")
    parser.add_argument("--cookies", type=str, help="JSON string of cookies to use for authentication")
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    iterations = 1 if args.deploy_only else args.iterations

    try:
        for i in range(1, iterations + 1):
            print(f"\n{'='*40}")
            print(f"   STARTING ITERATION {i}/{iterations}")
            print(f"{'='*40}\n")
            
            iter_dir = os.path.join(RESULTS_DIR, f"result_{i}")
            os.makedirs(iter_dir, exist_ok=True)
            
            # 1. Reset Environment
            teardown()
            deploy()
            
            # Wait for all pods to be healthy
            pods_ready = wait_for_pods(timeout=300)
            if not pods_ready:
                print("[!] WARNING: Some pods are unhealthy. Proceeding anyway to scan what is alive.")
                if args.deploy_only:
                    print("[*] Deploy-only mode: leaving environment as-is for debugging.")
                    return
                
            print("\n=== STARTING BACKGROUND PROCESSES ===")
            # 2. Port Forwarding
            # Online Boutique frontend runs on port 80 internally
            pf_cmd = f"kubectl port-forward svc/frontend {FRONTEND_PORT}:80"
            pf_proc = subprocess.Popen(pf_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Give port-forward a moment
            time.sleep(5)
            
            # Check if localhost is actually reachable
            if not check_localhost():
                print("[!] WARNING: localhost is inaccessible. Proceeding anyway.")
                if args.deploy_only:
                    pf_proc.terminate()
                    return

            if args.deploy_only:
                print("\n[+] Deploy-only mode requested. Environment is ready and port-forward is running.")
                print("[*] Press Ctrl+C to terminate the port-forward.")
                try:
                    pf_proc.wait()
                except KeyboardInterrupt:
                    print("\n[*] Exiting deploy-only mode.")
                finally:
                    pf_proc.terminate()
                return

            # 3. Mitmdump (Proxy)
            dump_path = os.path.join(iter_dir, "traffic.mitm")
            mitm_cmd = f"mitmdump -w {dump_path} -p {PROXY_PORT}"
            mitm_proc = subprocess.Popen(mitm_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            
            # 4. Run Scanner
            # Online Boutique doesn't have an automated registration API, so we scan anonymously.
            # The crawler will discover the injected forms on /login on its own.
            print("\n=== RUNNING SCANNER ===")
            scanner_cmd = [
                "python3", "-m", "my_scan.scanner", 
                f"http://localhost:{FRONTEND_PORT}/", 
                iter_dir, 
                "--proxy", f"http://localhost:{PROXY_PORT}", 
                "--max-depth", "3"
            ]
            
            if args.cookies:
                scanner_cmd.extend(["--cookies", f"'{args.cookies}'"])

            try:
                run_cmd(" ".join(scanner_cmd))
            except subprocess.CalledProcessError as e:
                print(f"[!] Scanner failed on iteration {i}: {e}")
            finally:
                print("\n=== CLEANUP BACKGROUND PROCS ===")
                pf_proc.terminate()
                mitm_proc.terminate()
                pf_proc.wait()
                mitm_proc.wait()
                
                run_cmd("pkill -f 'kubectl port-forward svc/frontend'", check=False, capture_output=True)
                run_cmd("pkill -f 'mitmdump'", check=False, capture_output=True)
                
    finally:
        if not args.deploy_only:
            print("\n=== FINAL TEARDOWN ===")
            teardown()
            print("[+] All done. Environment cleaned up.")

if __name__ == "__main__":
    main()
