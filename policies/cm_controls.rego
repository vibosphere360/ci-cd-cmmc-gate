package cmmc

# CM.L2-3.4.3 — Track, review, approve, and log changes
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_logging"
  resource.change.after.target_bucket == ""
  msg := sprintf("CM.L2-3.4.3 VIOLATION: S3 bucket '%v' has logging disabled", [resource.address])
}

# CM.L2-3.4.2 — Establish settings for configuration management
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  not resource.change.after.tags["Environment"]
  msg := sprintf("CM.L2-3.4.2 VIOLATION: EC2 instance '%v' missing required Environment tag", [resource.address])
}
