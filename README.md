# ci-cd-cmmc-gate

[![Pipeline](https://img.shields.io/badge/pipeline-active-brightgreen)](https://github.com/vibosphere360/ci-cd-cmmc-gate)
[![CMMC Level 2](https://img.shields.io/badge/CMMC-Level%202-blue)](https://dodcio.defense.gov/CMMC/)
[![NIST 800-171](https://img.shields.io/badge/NIST-800--171-blue)](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)

CI/CD pipeline automating CMMC 2.0 compliance gates with OPA policies, AI remediation, and NIST 800-171 evidence collection.

## What this does

Every code commit automatically:
1. Scans for CUI markers, secrets, and PII (AC.L1-3.1.1, SC.L2-3.13.16)
2. Validates Terraform IaC against CMMC controls via Checkov
3. Enforces 47 CMMC practices as OPA Rego policy gates — blocks merge on violation
4. Uploads KMS-encrypted, SHA256-signed evidence package to S3 (AU.L2-3.3.1)
5. Uses Anthropic Claude API to generate remediation guidance for violations
6. Produces HTML compliance scorecard for leadership reporting

## Architecture
Developer push → GitLab CI (self-hosted on AWS EC2)
├── Stage 1: CUI scan (detect-secrets + Presidio + semgrep)
├── Stage 2: IaC validate (Checkov + model provenance)
├── Stage 3: OPA gates (47 CMMC Rego policies — EXIT 1 on CRITICAL)
├── Stage 4: Evidence collect (KMS-encrypted S3 bundle + SHA256)
├── Stage 5: AI analysis (Claude API remediation + SSP narratives)
└── Stage 6: Compliance report (HTML dashboard)

## CMMC Controls Covered

| Family | Controls | Pipeline stage |
|--------|----------|----------------|
| AC — Access Control | AC.L1-3.1.1, AC.L1-3.1.2, AC.L2-3.1.7 | Stage 1, 3 |
| CM — Configuration | CM.L2-3.4.2, CM.L2-3.4.3 | Stage 2, 3 |
| SC — System & Comms | SC.L2-3.13.8, SC.L2-3.13.10, SC.L2-3.13.16 | Stage 1, 3 |
| SI — System Integrity | SI.L1-3.14.1, SI.L2-3.14.6 | Stage 1, 3 |
| AU — Audit | AU.L2-3.3.1, AU.L2-3.3.2 | Stage 4 |

## Infrastructure

- **AWS Region:** us-east-2
- **CUI Boundary:** Private VPC with GitLab runner in private subnet
- **Evidence Store:** S3 with KMS encryption (alias/cmmc-evidence)
- **Audit Trail:** CloudTrail multi-region with log file validation
- **IaC:** Terraform with S3 backend state

## Books and frameworks

- Vehent — *Securing DevOps* (Chs 4, 5, 6, 8, 9, 11)
- Bozdag/Bennati — *AI Governance* (six-level framework, Ch 3-5)
- NIST SP 800-171 Rev 2
- CMMC 2.0 Assessment Guide Level 2
- MITRE ATLAS v4.0 (AI threat mapping)

## Author

Victor Adeleke | victorsreops@gmail.com | [grcsecuritycontrols.com](https://grcsecuritycontrols.com)
