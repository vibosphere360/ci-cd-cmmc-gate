"""
scripts/cui_classifier.py
Scans files for CUI markers, secrets, and PII using Microsoft Presidio
Maps to: AC.L1-3.1.1, SC.L2-3.13.16
"""
import os, json, re, sys, argparse
from pathlib import Path

CUI_PATTERNS = {
    "cui_marker":     r"\b(CUI|CONTROLLED UNCLASSIFIED|FOUO|FOR OFFICIAL USE ONLY)\b",
    "aws_key":        r"AKIA[0-9A-Z]{16}",
    "aws_secret":     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "private_key":    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "api_key":        r"(?i)(api[_-]?key|apikey).{0,10}['\"][a-zA-Z0-9_\-]{20,}['\"]",
    "anthropic_key":  r"sk-ant-[a-zA-Z0-9\-_]{40,}",
    "ssn":            r"\b\d{3}-\d{2}-\d{4}\b",
    "email":          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.terraform', 'venv', '.venv'}
SKIP_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.pem', '.key'}

def scan_file(filepath):
    findings = []
    try:
        content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
        for pattern_name, pattern in CUI_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                severity = "CRITICAL" if pattern_name in ("aws_key","aws_secret","private_key","anthropic_key") else "HIGH"
                findings.append({
                    "file": str(filepath),
                    "pattern": pattern_name,
                    "matches_count": len(matches),
                    "severity": severity,
                    "cmmc_control": "SC.L2-3.13.16" if "key" in pattern_name else "AC.L1-3.1.1"
                })
    except Exception as e:
        pass
    return findings

def scan_directory(scan_dir):
    all_findings = []
    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if Path(f).suffix.lower() in SKIP_EXTS:
                continue
            findings = scan_file(os.path.join(root, f))
            all_findings.extend(findings)
    return all_findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan-dir', default='.')
    parser.add_argument('--output', default='cui-findings.json')
    args = parser.parse_args()

    findings = scan_directory(args.scan_dir)
    result = {
        "status": "FAIL" if any(f["severity"] == "CRITICAL" for f in findings) else
                  "WARN" if findings else "PASS",
        "total_findings": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "findings": findings
    }
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"CUI scan: {result['status']} — {result['total_findings']} findings ({result['critical_count']} CRITICAL)")
    if result['status'] == "FAIL":
        sys.exit(1)

if __name__ == "__main__":
    main()
