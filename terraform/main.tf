terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Environment = "Production"
      ManagedBy   = "Terraform"
      Compliance  = "CIS-AWS-Foundations-v3.0"
    }
  }
}

# -----------------------------------------------------------------------------
# 1. HARDENED S3 BUCKET (CIS 2.1.1, CIS 2.1.5)
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "s3_kms_key" {
  description             = "KMS CMK for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "finance_archive" {
  bucket        = "finance-backup-archive-2026"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "finance_archive_versioning" {
  bucket = aws_s3_bucket.finance_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "finance_archive_encryption" {
  bucket = aws_s3_bucket.finance_archive.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "finance_archive_pab" {
  bucket = aws_s3_bucket.finance_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "enforce_tls" {
  bucket = aws_s3_bucket.finance_archive.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.finance_archive.arn,
          "${aws_s3_bucket.finance_archive.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# 2. HARDENED SECURITY GROUPS (CIS 5.2, CIS 5.3)
# -----------------------------------------------------------------------------

resource "aws_security_group" "app_mgmt_sg" {
  name        = "app-mgmt-sg"
  description = "Administrative SG restricted to internal CIDRs; no 0.0.0.0/0 ingress"
  vpc_id      = "vpc-0123456789abcdef0"

  # Port 22 SSH restricted to Internal Corporate VPN CIDR
  ingress {
    description = "SSH ingress restricted to internal VPN CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.100.4.0/24"]
  }

  # Port 3389 RDP restricted to dedicated bastion host IP
  ingress {
    description = "RDP ingress restricted to dedicated bastion host IP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["10.100.8.10/32"]
  }

  egress {
    description = "Restricted outbound HTTPS for updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------------------
# 3. SECURE IAM ARCHITECTURE (CIS 1.5, CIS 1.14)
# -----------------------------------------------------------------------------

# AssumeRole pattern enforcing MFA to remove stale programmatic access keys
resource "aws_iam_role" "ci_worker_role" {
  name = "dev-ci-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ci_least_privilege_policy" {
  name        = "ci-worker-least-privilege"
  description = "Scoped S3 access policy without wildcard actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.finance_archive.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ci_worker_attach" {
  role       = aws_iam_role.ci_worker_role.name
  policy_arn = aws_iam_policy.ci_least_privilege_policy.arn
}
