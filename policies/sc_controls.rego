package cmmc

# SC.L2-3.13.16 — Protect CUI at rest
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  msg := sprintf("SC.L2-3.13.16 VIOLATION: S3 bucket '%v' lacks SSE encryption", [resource.address])
}

# SC.L2-3.13.8 — Implement cryptographic mechanisms
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  rule := resource.change.after.ingress[_]
  rule.from_port == 80
  rule.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("SC.L2-3.13.8 VIOLATION: Security group '%v' allows unencrypted HTTP inbound", [resource.address])
}

# SC.L2-3.13.10 — Key rotation required
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_kms_key"
  resource.change.after.enable_key_rotation == false
  msg := sprintf("SC.L2-3.13.10 VIOLATION: KMS key '%v' does not have rotation enabled", [resource.address])
}
