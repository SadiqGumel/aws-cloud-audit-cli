package terraform.security

import future.keywords.in

default allow := false

# List of prohibited administrative ports exposed to the public internet
prohibited_ports := [22, 3389]

# Helper rule to extract resource changes from Terraform plan
resource_changes[resource] {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.actions[_] in ["create", "update"]
}

# Deny security group ingress rules with 0.0.0.0/0 or ::/0 on prohibited ports
deny[msg] {
    some resource in resource_changes
    ingress := resource.change.after.ingress[_]

    # Check for public internet CIDR exposure
    is_public_exposure(ingress)

    # Check port overlap
    exposes_prohibited_port(ingress, prohibited_ports[_])

    msg := sprintf(
        "OPA VIOLATION: Security Group '%v' allows unrestricted ingress (0.0.0.0/0) on sensitive port range %v-%v. Public management access is prohibited.",
        [resource.address, ingress.from_port, ingress.to_port]
    )
}

# Evaluate if rule allows public internet access
is_public_exposure(ingress) {
    "0.0.0.0/0" in ingress.cidr_blocks
}

is_public_exposure(ingress) {
    "::/0" in ingress.ipv6_cidr_blocks
}

# Evaluate if ingress rule spans over the target prohibited port
exposes_prohibited_port(ingress, target_port) {
    ingress.from_port <= target_port
    ingress.to_port >= target_port
}

# Catch wildcard protocol allowing all ports (-1)
exposes_prohibited_port(ingress, _) {
    ingress.protocol == "-1"
}
