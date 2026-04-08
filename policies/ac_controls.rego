package cmmc

# AC.L1-3.1.1 — Limit system access to authorized users
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.after.acl == "public-read"
  msg := sprintf("AC.L1-3.1.1 VIOLATION: S3 bucket '%v' has public-read ACL", [resource.address])
}

# AC.L1-3.1.2 — Limit system access to authorized transactions
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  rule := resource.change.after.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port == 22
  msg := sprintf("AC.L1-3.1.2 VIOLATION: Security group '%v' allows unrestricted SSH from 0.0.0.0/0", [resource.address])
}

# AC.L2-3.1.7 — Prevent non-privileged users from executing privileged functions
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user_policy"
  contains(resource.change.after.policy, "\"Effect\":\"Allow\"")
  contains(resource.change.after.policy, "\"Action\":\"*\"")
  msg := sprintf("AC.L2-3.1.7 VIOLATION: IAM user policy '%v' grants wildcard permissions", [resource.address])
}
