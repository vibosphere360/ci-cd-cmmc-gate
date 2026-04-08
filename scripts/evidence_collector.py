"""
scripts/evidence_collector.py
Packages all stage outputs into a KMS-encrypted S3 evidence bundle
Maps to: AU.L2-3.3.1, AU.L2-3.3.2
"""
import json, os, hashlib, boto3, argparse
from datetime import datetime

def hash_file(path):
    if not os.path.exists(path):
        return None
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pipeline-id', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--bucket', required=True)
    parser.add_argument('--kms-key', required=True)
    args = parser.parse_args()

    stage_files = [
        "cui-findings.json", "dep-scan.json", "sast-findings.json",
        "pii-collection-report.json", "iac-findings.json", "opa-results.json",
        "model-provenance.json", "ai-governance-report.json",
        "lineage-log.json", "control-map.json"
    ]

    bundle = {
        "pipeline_id": args.pipeline_id,
        "project": args.project,
        "timestamp": datetime.utcnow().isoformat(),
        "git_sha": os.environ.get("CI_COMMIT_SHA", "local"),
        "branch": os.environ.get("CI_COMMIT_REF_NAME", "main"),
        "committer": os.environ.get("GITLAB_USER_EMAIL", "local"),
        "stage_evidence": {},
        "integrity_hashes": {}
    }

    for fname in stage_files:
        if os.path.exists(fname):
            with open(fname) as f:
                try:
                    bundle["stage_evidence"][fname] = json.load(f)
                except:
                    bundle["stage_evidence"][fname] = {"raw": open(fname).read()}
            bundle["integrity_hashes"][fname] = hash_file(fname)

    bundle_path = "evidence-bundle.json"
    with open(bundle_path, 'w') as f:
        json.dump(bundle, f, indent=2)

    # Upload to S3 with KMS encryption
    s3 = boto3.client('s3')
    key = f"evidence/{args.project}/{args.pipeline_id}/bundle.json"
    s3.put_object(
        Bucket=args.bucket,
        Key=key,
        Body=json.dumps(bundle, indent=2).encode(),
        ServerSideEncryption='aws:kms',
        SSEKMSKeyId=args.kms_key,
        ContentType='application/json'
    )
    print(f"Evidence bundle uploaded: s3://{args.bucket}/{key}")

if __name__ == "__main__":
    main()
