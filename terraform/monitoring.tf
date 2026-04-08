resource "aws_cloudtrail" "cmmc_audit" {
  name                          = "cmmc-pipeline-audit-trail"
  s3_bucket_name                = "ci-cd-cmmc-gate-evidence-vadeleke-vibosphere"
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.evidence.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::ci-cd-cmmc-gate-evidence-vadeleke-vibosphere/"]
    }
  }
}
