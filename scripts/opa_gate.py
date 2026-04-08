"""
scripts/opa_gate.py
Reads OPA results and exits 1 if any CRITICAL or HIGH violations found
"""
import json, sys

with open("opa-results.json") as f:
    results = json.load(f)

violations = results.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])

if not isinstance(violations, list):
    violations = []

critical = [v for v in violations if "CRITICAL" in str(v) or "SC.L2-3.13.16" in str(v)]
high = [v for v in violations if "HIGH" in str(v) or "VIOLATION" in str(v)]

print(f"OPA gate: {len(violations)} violations ({len(critical)} block-level)")

for v in violations:
    print(f"  VIOLATION: {v}")

if violations:
    print("\nPipeline BLOCKED — fix violations before merging")
    sys.exit(1)
else:
    print("OPA gate: PASS — all CMMC controls satisfied")
