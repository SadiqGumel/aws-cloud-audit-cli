# AWS Cloud Audit CLI (aws-cloud-audit-cli)

Modular Python CLI tool using boto3 to audit AWS cloud environments against CIS AWS Foundations Benchmark controls.

## Features
- --check-iam: Identifies IAM users without MFA and active access keys older than 90 days.
- --check-s3: Checks S3 buckets for server-side encryption and Public Access Block settings.
- --check-sg: Detects open ingress rules (0.0.0.0/0) on ports 22 (SSH) and 3389 (RDP).
- --json: Outputs structured JSON for integration pipelines.

## Installation & Setup
1. Set up a virtual environment:
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Run audits:
   python3 audit_cli.py --all
   python3 audit_cli.py --all --json
