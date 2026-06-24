import json
import re
import os
import sys

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

    fp_endpoints = set()
    for f in findings:
        f_path = get_path(f["url"])
        f_type = f.get("vulnerability_type", "")
        f_param = f.get("parameter", "")
        f_method = f.get("method", "")
        mapped_type = type_mapping.get(f_type, f_type)
        
        is_gt = False
        for gt in ground_truth:
            if gt["url_pattern"] in f_path and f_method.upper() == gt["method"].upper() and f_param == gt["parameter"]:
                if mapped_type == gt["type"] or f_type == gt["type"]:
                    is_gt = True
                    break
        
        if not is_gt and mapped_type in injected_types:
            comb = f"{f_method} {f_path} [{f_param}]"
            is_secure = False
            for s in secure_endpoints:
                if s == f_path or s == comb:
                    is_secure = True
                    break
            if is_secure:
                fp_endpoints.add(comb)

    fp = len(fp_endpoints)

    tn = 0
    for s in secure_endpoints:
        has_finding = False
        for f in findings:
            f_path = get_path(f["url"])
            f_type = f.get("vulnerability_type", "")
            f_param = f.get("parameter", "")
            f_method = f.get("method", "")
            mapped_type = type_mapping.get(f_type, f_type)
            comb = f"{f_method} {f_path} [{f_param}]"
            if mapped_type in injected_types:
                if s == f_path or s == comb:
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
    if len(sys.argv) < 4:
        print("Usage: python3 analyze_results.py <results_dir> <ground_truth.json> <secure_endpoints.json>")
        sys.exit(1)

    results_dir = sys.argv[1]
    ground_truth_file = sys.argv[2]
    secure_endpoints_file = sys.argv[3]

    with open(ground_truth_file, "r") as f:
        ground_truth = json.load(f)
    print(f"Loaded {len(ground_truth)} ground truth vulnerabilities.")

    with open(secure_endpoints_file, "r") as f:
        secure_endpoints = json.load(f)
    print(f"Loaded {len(secure_endpoints)} secure endpoints from file.")

    injected_types = {
        "sqli", "sqli_blind", "sqli_auth_bypass", "xss", "ssti", "cmdi", 
        "cmdi_blind", "path_traversal", "ssrf", "crlf", "open_redirect", "nosql_manipulation"
    }

    type_mapping = {
        "sqli": "sqli", "potential_sqli": "sqli", "sqli_blind": "sqli", "sqli_auth_bypass": "sqli",
        "xss": "xss", "potential_xss": "xss", "potential_ssti": "ssti",
        "cmdi": "cmdi", "cmdi_blind": "cmdi", "potential_cmdi": "cmdi",
        "path_traversal": "path_traversal", "potential_path_traversal": "path_traversal", "ssrf": "misconfig",
        "missing_header": "misconfig", "info_disclosure": "misconfig", "cors": "misconfig", "insecure_cookie": "misconfig", "open_redirect": "misconfig", "potential_open_redirect": "misconfig", "crlf": "misconfig", "potential_crlf": "misconfig", "potential_ssrf": "misconfig"
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

    avg_tp = sum(m["tp"] for m in iteration_metrics) / len(iteration_metrics)
    avg_fn = sum(m["fn"] for m in iteration_metrics) / len(iteration_metrics)
    avg_fp = sum(m["fp"] for m in iteration_metrics) / len(iteration_metrics)
    avg_tn = sum(m["tn"] for m in iteration_metrics) / len(iteration_metrics)
    avg_fpr = sum(m["fpr"] for m in iteration_metrics) / len(iteration_metrics)
    avg_fnr = sum(m["fnr"] for m in iteration_metrics) / len(iteration_metrics)
    avg_precision = sum(m["precision"] for m in iteration_metrics) / len(iteration_metrics)
    avg_recall = sum(m["recall"] for m in iteration_metrics) / len(iteration_metrics)

    summary = f"""--- AVERAGE METRICS ACROSS ALL ITERATIONS ---
Number of iterations analyzed: {len(iteration_metrics)}
Average True Positives (TP): {avg_tp} / {len(ground_truth)}
Average False Negatives (FN): {avg_fn} / {len(ground_truth)}
Average False Positives (FP): {avg_fp} / {len(secure_endpoints)}
Average True Negatives (TN): {avg_tn} / {len(secure_endpoints)}
-------------------------------------------------
Average Type I Error Rate (FPR): {avg_fpr * 100:.2f}%
Average Type II Error Rate (FNR): {avg_fnr * 100:.2f}%
Average Precision: {avg_precision * 100:.2f}%
Average Recall: {avg_recall * 100:.2f}%
"""

    print(summary)
    
    with open(os.path.join(results_dir, "metrics_summary.txt"), "w") as f:
        f.write(summary)
    print(f"[+] Saved metrics summary to {os.path.join(results_dir, 'metrics_summary.txt')}")

if __name__ == "__main__":
    main()
