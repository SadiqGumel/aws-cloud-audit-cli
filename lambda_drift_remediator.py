import os
import json
import logging
import urllib.request
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
sns_client = boto3.client("sns")
ssm_client = boto3.client("ssm")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
SSM_PARAM_NAME = os.environ.get("SSM_PARAM_NAME", "/security/remediator/slack_webhook_url")
PROHIBITED_PORTS = {22, 3389}

CACHED_SLACK_WEBHOOK = None

def get_slack_webhook():
    global CACHED_SLACK_WEBHOOK
    if CACHED_SLACK_WEBHOOK:
        return CACHED_SLACK_WEBHOOK

    try:
        response = ssm_client.get_parameter(Name=SSM_PARAM_NAME, WithDecryption=True)
        CACHED_SLACK_WEBHOOK = response["Parameter"]["Value"]
        return CACHED_SLACK_WEBHOOK
    except Exception as err:
        logger.warning("Could not fetch webhook from SSM (%s). Checking env vars: %s", SSM_PARAM_NAME, err)
        return os.environ.get("SLACK_WEBHOOK_URL")

def send_slack_notification(message_text):
    webhook_url = get_slack_webhook()
    if not webhook_url or "XXXX" in webhook_url:
        logger.warning("Valid Slack webhook not available. Skipping Slack alert.")
        return

    payload = json.dumps({"text": message_text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info("Slack notification posted. Status code: %s", resp.status)
    except Exception as err:
        logger.error("Failed to post to Slack: %s", err)

def handle_ec2_drift(detail, actor):
    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")
    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])

    if not group_id or not ip_permissions:
        return []

    remediated_rules = []
    for perm in ip_permissions:
        ip_protocol = perm.get("ipProtocol", "")
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")

        # Check prohibited ports
        is_prohibited = (ip_protocol == "-1") or (
            from_port is not None and to_port is not None and 
            any(from_port <= p <= to_port for p in PROHIBITED_PORTS)
        )
        if not is_prohibited:
            continue

        # Revoke IPv4
        for cidr_entry in perm.get("ipRanges", {}).get("items", []):
            if cidr_entry.get("cidrIp") == "0.0.0.0/0":
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{"IpProtocol": ip_protocol, "FromPort": from_port, "ToPort": to_port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
                    )
                    logger.info("Successfully revoked 0.0.0.0/0 ingress on port %s from %s", from_port, group_id)
                    remediated_rules.append({"port": from_port, "cidr": "0.0.0.0/0"})
                except ClientError as e:
                    logger.error("Error revoking IPv4: %s", e)

        # Revoke IPv6
        for cidr_entry in perm.get("ipv6Ranges", {}).get("items", []):
            if cidr_entry.get("cidrIpv6") == "::/0":
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{"IpProtocol": ip_protocol, "FromPort": from_port, "ToPort": to_port, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
                    )
                    logger.info("Successfully revoked ::/0 ingress on port %s from %s", from_port, group_id)
                    remediated_rules.append({"port": from_port, "cidr": "::/0"})
                except ClientError as e:
                    logger.error("Error revoking IPv6: %s", e)

    if remediated_rules:
        msg = f"[REMEDIATED] Unauthorized SSH rule revoked on {group_id}."
        send_slack_notification(msg)

    return remediated_rules

def handle_iam_drift(event_name, detail, actor):
    target = detail.get("requestParameters", {}).get("roleName") or detail.get("requestParameters", {}).get("userName", "Unknown")
    policy_arn = detail.get("requestParameters", {}).get("policyArn", "Inline-Policy")
    
    logger.warning("HIGH SEVERITY: IAM Drift detected! Event: %s, Target: %s, Policy: %s, Actor: %s", event_name, target, policy_arn, actor)
    
    alert_msg = f"[IAM ALERT] Out-of-band policy modification detected! Action: {event_name} on {target} by {actor}."
    send_slack_notification(alert_msg)

def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    detail = event.get("detail", {})
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")
    actor = detail.get("userIdentity", {}).get("arn", "Unknown-Actor")

    if event_source == "ec2.amazonaws.com" and event_name == "AuthorizeSecurityGroupIngress":
        remediated = handle_ec2_drift(detail, actor)
        return {"statusCode": 200, "remediated_count": len(remediated)}

    elif event_source == "iam.amazonaws.com":
        handle_iam_drift(event_name, detail, actor)
        return {"statusCode": 200, "message": "IAM drift event audited and alerted"}

    return {"statusCode": 200, "message": "Unhandled event source ignored"}
