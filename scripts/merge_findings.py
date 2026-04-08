"""
scripts/merge_findings.py
Combines all stage JSON outputs into merged-findings.json for OPA evaluation
"""
import json, os, glob

def load_json_safe(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return {}

merged = {
    "resource_changes": [],
    "vulnerabilities":  [],
    "sast_findings":    [],
    "cui_findings":     [],
    "iac_findings":     [],
}

if os.path.exists("iac-findings.json"):
    iac = load_json_safe("iac-findings.json")
    merged["resource_changes"] = iac.get("resource_changes", [])

if os.path.exists("dep-scan.json"):
    dep = load_json_safe("dep-scan.json")
    for vuln in dep.get("vulnerabilities", []):
        merged["vulnerabilities"].append({
            "id": vuln.get("id", ""),
            "package": vuln.get("package", {}).get("name", ""),
            "severity": vuln.get("fix", {}).get("versions", [""])[0] and "CRITICAL" or "HIGH"
        })

if os.path.exists("sast-findings.json"):
    sast = load_json_safe("sast-findings.json")
    for result in sast.get("results", []):
        merged["sast_findings"].append({
            "path": result.get("path", ""),
            "message": result.get("extra", {}).get("message", ""),
            "severity": result.get("extra", {}).get("severity", "INFO")
        })

if os.path.exists("cui-findings.json"):
    cui = load_json_safe("cui-findings.json")
    merged["cui_findings"] = cui.get("findings", [])

with open("merged-findings.json", "w") as f:
    json.dump(merged, f, indent=2)

print(f"Merged findings: {sum(len(v) for v in merged.values() if isinstance(v, list))} total items")
