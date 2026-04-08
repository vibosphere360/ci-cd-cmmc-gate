package cmmc

# AU.L2-3.3.1 — Create and retain audit logs
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"
  resource.change.after.enable_log_file_validation == false
  msg := sprintf("AU.L2-3.3.1 VIOLATION: CloudTrail '%v' log file validation disabled", [resource.address])
}

# AU.L2-3.3.2 — Ensure user actions are traceable
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"
  resource.change.after.is_multi_region_trail == false
  msg := sprintf("AU.L2-3.3.2 VIOLATION: CloudTrail '%v' is not multi-region", [resource.address])
}
