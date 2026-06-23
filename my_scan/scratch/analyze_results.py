import json
import re
import os
import sys
# cd /Users/mac/Desktop/sacner/scaner_1
# ./run_tests.sh


def get_path(url):
    if "://" in url:
        path = "/" + "/".join(url.split("://")[1].split("/")[1:])
    else:
        path = url
    path = path.split("?")[0]
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path

def analyze_report(report_path, ground_truth, secure_endpoints, injected_types, type_mapping):
    with open(report_path, "r") as f:
        report = json.load(f)

    findings = report.get("vulnerabilities", [])
    
    tp = 0
    fn = 0
    fp = 0
    tn = 0

    detected_ground_truth = set()
    for idx, gt in enumerate(ground_truth):
        matched = False
        for f in findings:
            f_path = get_path(f["url"])
            f_param = f.get("parameter", "")
            f_type = f.get("vulnerability_type", "")
            f_method = f.get("method", "")
            
            # Match by URL pattern, Method, Parameter, and Vulnerability Type Category
            if gt["url_pattern"] in f_path and f_method.upper() == gt["method"].upper() and f_param == gt["parameter"]:
                mapped_type = type_mapping.get(f_type, f_type)
                if mapped_type == gt["type"] or f_type == gt["type"]:
                    matched = True
                    break
        if matched:
            tp += 1
            detected_ground_truth.add(idx)
        else:
            fn += 1

    # Any finding that doesn't map to a ground truth item but is within `secure_endpoints` or paths
    fp_endpoints = set()
    for f in findings:
        f_path = get_path(f["url"])
        f_type = f.get("vulnerability_type", "")
        f_param = f.get("parameter", "")
        f_method = f.get("method", "")
        mapped_type = type_mapping.get(f_type, f_type)
        
        # Check if it was part of ground truth
        is_gt = False
        for gt in ground_truth:
            if gt["url_pattern"] in f_path and f_method.upper() == gt["method"].upper() and f_param == gt["parameter"]:
                if mapped_type == gt["type"] or f_type == gt["type"]:
                    is_gt = True
                    break
        
        if not is_gt and mapped_type in injected_types:
            is_secure = False
            for s in secure_endpoints:
                if f_path == s or f_path.startswith("/product/"):
                    is_secure = True
                    break
            if is_secure:
                fp_endpoints.add(f"{f_method} {f_path} [{f_param}]")

    fp = len(fp_endpoints)

    tn = 0
    for s in secure_endpoints:
        has_finding = False
        for f in findings:
            f_path = get_path(f["url"])
            f_type = f.get("vulnerability_type", "")
            mapped_type = type_mapping.get(f_type, f_type)
            if mapped_type in injected_types:
                if f_path == s or (s == "/product/1YAFDFK15C" and f_path.startswith("/product/")):
                    has_finding = True
                    break
        if not has_finding:
            tn += 1

    total_gt = len(ground_truth)
    fpr = fp / len(secure_endpoints) if len(secure_endpoints) > 0 else 0
    fnr = fn / total_gt if total_gt > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / total_gt if total_gt > 0 else 0

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "fpr": fpr, "fnr": fnr, "precision": precision, "recall": recall,
        "total_findings": len(findings)
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_results.py <results_dir> <ground_truth.json>")
        sys.exit(1)

    results_dir = sys.argv[1]
    ground_truth_file = sys.argv[2]

    # Parse ground truth from JSON
    with open(ground_truth_file, "r") as f:
        ground_truth = json.load(f)

    print(f"Loaded {len(ground_truth)} ground truth vulnerabilities.")

    secure_endpoints = [
        "/", "/assistant", "/cart", "/logout", "/robots.txt", "/_healthz",
        "/static/icons/Hipster_HeroLogoMaroon.svg", "/product/OLJ35I2N9E",
        "/product/66V1O25JQ2", "/product/1YAFDFK15C"
    ]

    injected_types = {
        "sqli", "sqli_blind", "sqli_auth_bypass", "xss", "ssti", "cmdi", 
        "cmdi_blind", "path_traversal", "ssrf", "crlf", "open_redirect", "nosql_manipulation"
    }

    type_mapping = {
        "sqli": "sqli", "potential_sqli": "sqli", "sqli_blind": "sqli",
        "xss": "xss", "potential_xss": "xss", "potential_ssti": "ssti",
        "cmdi_blind": "cmdi", "potential_cmdi": "cmdi",
        "potential_path_traversal": "path_traversal", "ssrf": "ssrf",
        "potential_ssrf": "ssrf", "crlf": "crlf", "potential_crlf": "crlf",
        "potential_open_redirect": "open_redirect", "nosql_manipulation": "nosql_manipulation"
    }

    iteration_metrics = []

    if not os.path.exists(results_dir):
        print(f"Directory {results_dir} does not exist.")
        sys.exit(1)

    for item in os.listdir(results_dir):
        item_path = os.path.join(results_dir, item)
        if os.path.isdir(item_path) and item.startswith("result_"):
            report_path = os.path.join(item_path, "report.json")
            if os.path.exists(report_path):
                print(f"Analyzing {report_path}...")
                metrics = analyze_report(report_path, ground_truth, secure_endpoints, injected_types, type_mapping)
                iteration_metrics.append(metrics)
                
    if not iteration_metrics:
        print("No report.json files found in the specified directory.")
        sys.exit(0)

    avg_tp = sum(m["tp"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_fp = sum(m["fp"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_fn = sum(m["fn"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_tn = sum(m["tn"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    
    avg_fpr = sum(m["fpr"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_fnr = sum(m["fnr"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_precision = sum(m["precision"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    avg_recall = sum(m["recall"] for m in iteration_metrics) / len(iteration_metrics) if len(iteration_metrics) > 0 else 0
    
    output_lines = [
        "",
        "--- AVERAGE METRICS ACROSS ALL ITERATIONS ---",
        f"Number of iterations analyzed: {len(iteration_metrics)}",
        f"Average True Positives (TP): {avg_tp:.1f} / {len(ground_truth)}",
        f"Average False Negatives (FN): {avg_fn:.1f} / {len(ground_truth)}",
        f"Average False Positives (FP): {avg_fp:.1f} / {len(secure_endpoints)}",
        f"Average True Negatives (TN): {avg_tn:.1f} / {len(secure_endpoints)}",
        "-------------------------------------------------",
        f"Average Type I Error Rate (FPR): {avg_fpr:.2%}",
        f"Average Type II Error Rate (FNR): {avg_fnr:.2%}",
        f"Average Precision: {avg_precision:.2%}",
        f"Average Recall: {avg_recall:.2%}"
    ]
    
    summary_text = "\n".join(output_lines)
    print(summary_text)
    
    summary_file = os.path.join(results_dir, "metrics_summary.txt")
    with open(summary_file, "w") as f:
        f.write(summary_text)
    print(f"\n[+] Saved metrics summary to {summary_file}")

if __name__ == "__main__":
    main()
