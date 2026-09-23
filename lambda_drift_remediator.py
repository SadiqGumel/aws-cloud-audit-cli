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

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PROHIBITED_PORTS = {22, 3389}

def is_port_prohibited(from_port, to_port, protocol):
    if protocol == "-1":
        return True
    if from_port is not None and to_port is not None:
        for port in PROHIBITED_PORTS:
            if from_port <= port <= to_port:
                return True
    return False

def send_slack_notification(message_text):
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not configured. Skipping Slack alert.")
        return
    payload = json.dumps({"text": message_text}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info("Slack notification sent successfully. Response code: %s", resp.status)
    except Exception as err:
        logger.error("Failed to post notification to Slack: %s", err)

def lambda_handler(event, context):
    logger.info("Received EventBridge CloudTrail event: %s", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    actor = detail.get("userIdentity", {}).get("arn", "Unknown-Actor")

    if event_name != "AuthorizeSecurityGroupIngress":
        logger.info("Ignoring non-ingress event: %s", event_name)
        return {"statusCode": 200, "body": "Event ignored"}

    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")
    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])

    if not group_id or not ip_permissions:
        logger.warning("Missing groupId or ipPermissions in event details.")
        return {"statusCode": 400, "body": "Invalid event parameters"}

    remediated_rules = []

    for perm in ip_permissions:
        ip_protocol = perm.get("ipProtocol", "")
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")

        if not is_port_prohibited(from_port, to_port, ip_protocol):
            continue

        # 1. IPv4 (0.0.0.0/0) Remediation
        for cidr_entry in perm.get("ipRanges", {}).get("items", []):
            if cidr_entry.get("cidrIp") == "0.0.0.0/0":
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            "IpProtocol": ip_protocol,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }]
                    )
                    logger.info("Successfully revoked 0.0.0.0/0 ingress on port %s from %s", from_port, group_id)
                    remediated_rules.append({"protocol": ip_protocol, "port": from_port, "cidr": "0.0.0.0/0"})
                except ClientError as err:
                    logger.error("Failed to revoke IPv4 rule from %s: %s", group_id, err)

        # 2. IPv6 (::/0) Remediation
        for cidr_entry in perm.get("ipv6Ranges", {}).get("items", []):
            if cidr_entry.get("cidrIpv6") == "::/0":
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            "IpProtocol": ip_protocol,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
                        }]
                    )
                    logger.info("Successfully revoked ::/0 ingress on port %s from %s", from_port, group_id)
                    remediated_rules.append({"protocol": ip_protocol, "port": from_port, "cidr": "::/0"})
                except ClientError as err:
                    logger.error("Failed to revoke IPv6 rule from %s: %s", group_id, err)

    # 3. Alerts Dispatch (SNS & Slack)
    if remediated_rules:
        slack_msg = f"[REMEDIATED] Unauthorized SSH rule revoked on {group_id}."
        send_slack_notification(slack_msg)

        if SNS_TOPIC_ARN:
            alert_payload = {
                "security_group_id": group_id,
                "remediated_rules": remediated_rules,
                "actor": actor,
                "status": "REMEDIATED"
            }
            try:
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"ALERT: Unauthorized SG Ingress Revoked on {group_id}",
                    Message=json.dumps(alert_payload, indent=2)
                )
            except ClientError as sns_err:
                logger.error("Failed to publish alert to SNS: %s", sns_err)

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Evaluation completed", "remediated_count": len(remediated_rules)})
    }
