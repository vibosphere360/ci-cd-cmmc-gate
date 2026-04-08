package cmmc

# SI.L1-3.14.1 — Identify and correct system flaws
deny contains msg if {
  vuln := input.vulnerabilities[_]
  vuln.severity == "CRITICAL"
  msg := sprintf("SI.L1-3.14.1 VIOLATION: Critical CVE '%v' found in '%v'", [vuln.id, vuln.package])
}

# SI.L2-3.14.6 — Monitor systems for security alerts
deny contains msg if {
  finding := input.sast_findings[_]
  finding.severity == "ERROR"
  msg := sprintf("SI.L2-3.14.6 VIOLATION: SAST found high-severity issue in '%v': %v", [finding.path, finding.message])
}
