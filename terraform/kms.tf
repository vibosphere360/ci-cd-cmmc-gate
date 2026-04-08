resource "aws_kms_key" "evidence" {
  description             = "CMMC evidence package encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/cmmc-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.evidence.arn
}
