# ==============================================================================
# Policy ID:        SEC-POL-IAC-001
# Title:            Zero-Trust AWS Security Group Ingress Restrictions
# Severity:         CRITICAL
# Target Engine:    Open Policy Agent (OPA) via Conftest
# Framework:        CIS AWS Foundations Benchmark v3.0 (Controls 5.2, 5.3)
# Description:      Enforces strict zero-trust boundary controls on Terraform HCL
#                   by denying public ingress (0.0.0.0/0 or ::/0) on sensitive
#                   management ports (SSH: 22, RDP: 3389) and wildcard protocols.
# ==============================================================================

package terraform.security

import future.keywords.in

# Default deny-all evaluation flag
default allow := false

# Prohibited sensitive management ports
prohibited_ports := [22, 3389]

# ------------------------------------------------------------------------------
# Rule: Deny Unrestricted Public Ingress on Sensitive Ports
# ------------------------------------------------------------------------------
# Trigger Conditions:
#   1. Resource is an aws_security_group with defined ingress blocks.
#   2. Ingress CIDR block exposes to internet (0.0.0.0/0 or ::/0).
#   3. Target port range encloses SSH (22), RDP (3389), or wildcard (-1).
# Remediation:
#   Constrain CIDR blocks to specific corporate VPC or bastion IP ranges.
# ------------------------------------------------------------------------------
deny[msg] {
    sg := input.resource.aws_security_group[_]
    ingress := sg.ingress[_]

    is_public_exposure(ingress)
    exposes_prohibited_port(ingress, prohibited_ports[_])

    msg := sprintf(
        "OPA VIOLATION [SEC-POL-IAC-001]: Security group allows unrestricted public ingress on sensitive port range %v-%v. Public management access violates Zero-Trust baseline.",
        [ingress.from_port, ingress.to_port]
    )
}

# ------------------------------------------------------------------------------
# Helper Functions: Public Exposure Identification
# ------------------------------------------------------------------------------

# Detects IPv4 public exposure (0.0.0.0/0)
is_public_exposure(ingress) {
    "0.0.0.0/0" in ingress.cidr_blocks
}

# Detects IPv6 public exposure (::/0)
is_public_exposure(ingress) {
    "::/0" in ingress.ipv6_cidr_blocks
}

# ------------------------------------------------------------------------------
# Helper Functions: Sensitive Port Range Matching
# ------------------------------------------------------------------------------

# Identifies if target prohibited port falls within rule port range
exposes_prohibited_port(ingress, target_port) {
    ingress.from_port <= target_port
    ingress.to_port >= target_port
}

# Identifies wildcard protocol exposure (protocol "-1" exposes all ports)
exposes_prohibited_port(ingress, _) {
    ingress.protocol == "-1"
}
