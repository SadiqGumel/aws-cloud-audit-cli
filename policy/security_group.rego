package terraform.security

import future.keywords.in

default allow := false

prohibited_ports := [22, 3389]

deny[msg] {
    sg := input.resource.aws_security_group[_]
    ingress := sg.ingress[_]

    is_public_exposure(ingress)
    exposes_prohibited_port(ingress, prohibited_ports[_])

    msg := sprintf(
        "OPA VIOLATION: Security group allows unrestricted ingress (0.0.0.0/0) on sensitive port range %v-%v.",
        [ingress.from_port, ingress.to_port]
    )
}

is_public_exposure(ingress) {
    "0.0.0.0/0" in ingress.cidr_blocks
}

is_public_exposure(ingress) {
    "::/0" in ingress.ipv6_cidr_blocks
}

exposes_prohibited_port(ingress, target_port) {
    ingress.from_port <= target_port
    ingress.to_port >= target_port
}

exposes_prohibited_port(ingress, _) {
    ingress.protocol == "-1"
}
