import json

gt = []
with open("/Users/mac/.gemini/antigravity-ide/brain/e399892a-758b-4b88-af89-41b4a3ea3e1d/ground_truth_and_metrics.md", "r") as f:
    for line in f:
        if line.startswith("|") and "GET" in line or "POST" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 7:
                url_pattern = parts[2].replace("`", "")
                method = parts[3]
                param = parts[5].replace("`", "").split(" ")[0]
                vuln_type = parts[6].replace("`", "")
                gt.append({
                    "url_pattern": url_pattern,
                    "method": method,
                    "parameter": param,
                    "type": vuln_type
                })

with open("ground_truth_goo.json", "w") as f:
    json.dump(gt, f, indent=2)

with open("ground_truth_un.json", "w") as f:
    json.dump(gt, f, indent=2)

print(f"Generated ground truth files with {len(gt)} items.")
