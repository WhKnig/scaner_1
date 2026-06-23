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

STAND_PATH = "/app/stand/unguard-light"
CHART_PATH = os.path.join(STAND_PATH, "chart")
RESULTS_DIR = "/app/my_scan/results_un"
PROXY_PORT = 8081
ENVOY_PORT = 8080

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
    run_cmd("helm uninstall unguard -n unguard", check=False, capture_output=True)
    run_cmd("helm uninstall unguard-mariadb -n unguard", check=False, capture_output=True)
    run_cmd("kubectl delete namespace unguard --wait=true", check=False, capture_output=True)
    
def deploy():
    print("=== DEPLOY ===")
    run_cmd("kubectl create namespace unguard", check=False, capture_output=True)
    
    print("[*] Adding bitnami repo...")
    run_cmd("helm repo add bitnami https://charts.bitnami.com/bitnami", check=False, capture_output=True)
    run_cmd("helm repo update", check=False, capture_output=True)

    print("[*] Installing MariaDB (in-memory)...")
    run_cmd(
        "helm install unguard-mariadb bitnami/mariadb "
        "--version 11.5.7 "
        "--set primary.persistence.enabled=false "
        "--set image.repository=bitnamilegacy/mariadb "
        "--namespace unguard",
        check=False, capture_output=True
    )
    print("[*] Waiting for MariaDB...")
    run_cmd("kubectl wait --for=condition=ready --timeout=300s pod -l app.kubernetes.io/name=mariadb -n unguard", check=False)
    
    print("[*] Installing Unguard...")
    run_cmd(f"helm install unguard {CHART_PATH} --namespace unguard", check=False, capture_output=True)

def wait_for_pods(timeout=600):
    print(f"\n[*] Waiting for ALL unguard pods to be ready (timeout {timeout}s)...")
    
    # Wait for the deployments specifically first
    run_cmd(f"kubectl wait --for=condition=available --timeout={timeout}s deployment --all -n unguard", check=False)
    
    # Wait for all individual pods to be ready
    result = run_cmd(f"kubectl wait --for=condition=ready pod --all -n unguard --timeout={timeout}s", check=False)
    
    if result.returncode == 0:
        print("[+] All pods are Running and Ready!")
        return True
    else:
        print("[!] ERROR: Timeout waiting for ALL pods to become ready.")
        run_cmd("kubectl get pods -n unguard", check=False)
        return False

def check_localhost():
    print("[*] Checking if localhost:8080/ui is accessible...")
    for _ in range(12):
        try:
            resp = requests.get("http://localhost:8080/ui", timeout=5)
            if resp.status_code < 500:
                print(f"[+] localhost:8080/ui is up! (Status: {resp.status_code})")
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    print("[!] ERROR: localhost:8080/ui is not reachable.")
    return False

def generate_random_string(length=10):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def register_user():
    username = f"user_{generate_random_string(6)}"
    password = f"P@ssw0rd_{generate_random_string(8)}!"
    
    print(f"[*] Attempting to register new user: {username}")
    
    # Try the user-auth service endpoints natively.
    # Usually, unguard proxy exposes it under /ui/api/auth/register or similar.
    register_urls = [
        "http://localhost:8080/user-auth/register",
        "http://localhost:8080/ui/api/auth/register"
    ]
    
    payload = {
        "username": username,
        "password": password,
        "email": f"{username}@example.com"
    }
    
    for url in register_urls:
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code in [200, 201]:
                print(f"[+] Successfully registered: {username} via {url}")
                return username, password
        except requests.RequestException:
            continue
            
    print("[!] Registration failed on all known endpoints. Scanner will proceed in anonymous mode.")
    return None, None

def main():
    parser = argparse.ArgumentParser(description="Automated Scanner Testing Stand")
    parser.add_argument("--iterations", type=int, default=10, help="Number of test iterations")
    parser.add_argument("--deploy-only", action="store_true", help="Deploy once, skip scanning, skip teardown")
    parser.add_argument("--no-auth", action="store_true", help="Do not attempt to register/authenticate")
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
            pf_cmd = f"kubectl port-forward svc/unguard-envoy-proxy {ENVOY_PORT}:8080 -n unguard"
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
            
            # 4. Registration
            username, password = None, None
            if not args.no_auth and not args.cookies:
                username, password = register_user()

            # 5. Run Scanner
            print("\n=== RUNNING SCANNER ===")
            scanner_cmd = [
                "python3", "-m", "my_scan.scanner", 
                f"http://localhost:{ENVOY_PORT}/ui", 
                iter_dir, 
                "--proxy", f"http://localhost:{PROXY_PORT}", 
                "--max-depth", "2"
            ]
            
            if username and password:
                scanner_cmd.extend(["--username", username, "--password", password])
            if args.cookies:
                # Wrap cookies string in single quotes to pass JSON safely
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
                
                run_cmd("pkill -f 'kubectl port-forward'", check=False, capture_output=True)
                run_cmd("pkill -f 'mitmdump'", check=False, capture_output=True)
                
    finally:
        if not args.deploy_only:
            print("\n=== FINAL TEARDOWN ===")
            teardown()
            print("[+] All done. Environment cleaned up.")

if __name__ == "__main__":
    main()
