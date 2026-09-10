import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
sns_client = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:cloud-drift-alerts")

def lambda_handler(event, context):
    logger.info("Received EventBridge CloudTrail event: %s", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    if event_name != "AuthorizeSecurityGroupIngress":
        logger.info("Event %s is not AuthorizeSecurityGroupIngress. Exiting.", event_name)
        return {"statusCode": 200, "body": "Skipped: Event not actionable"}

    actor = detail.get("userIdentity", {}).get("arn", "Unknown-Actor")
    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")

    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])
    if not ip_permissions and "ipProtocol" in request_params:
        ip_permissions = [{
            "ipProtocol": request_params.get("ipProtocol"),
            "fromPort": request_params.get("fromPort"),
            "toPort": request_params.get("toPort"),
            "ipRanges": request_params.get("ipRanges", {})
        }]

    remediated_rules = []

    for permission in ip_permissions:
        ip_ranges = permission.get("ipRanges", {}).get("items", [])
        public_ranges = [r for r in ip_ranges if r.get("cidrIp") == "0.0.0.0/0"]
        
        if public_ranges:
            protocol = permission.get("ipProtocol")
            from_port = permission.get("fromPort")
            to_port = permission.get("toPort")

            logger.warning(
                "DRIFT DETECTED: Unauthorized 0.0.0.0/0 ingress in %s on port %s-%s by %s",
                group_id, from_port, to_port, actor
            )

            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[{
                        "IpProtocol": protocol,
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }]
                )
                logger.info("Successfully revoked 0.0.0.0/0 ingress from %s", group_id)

                remediated_rules.append({
                    "Protocol": protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "CidrIp": "0.0.0.0/0"
                })

            except ClientError as err:
                logger.error("Failed to revoke security group ingress: %s", err)
                raise err

    if remediated_rules:
        payload = {
            "alert": "SECURITY_GROUP_DRIFT_AUTO_REMEDIATED",
            "severity": "CRITICAL",
            "actor": actor,
            "target_group_id": group_id,
            "remediated_rules": remediated_rules,
            "action_taken": "RevokeSecurityGroupIngress",
            "timestamp": detail.get("eventTime")
        }

        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"ALERT: Unauthorized SG Ingress Revoked on {group_id}",
                Message=json.dumps(payload, indent=2)
            )
            logger.info("Dispatched remediation notification to SNS Topic: %s", SNS_TOPIC_ARN)
        except ClientError as sns_err:
            logger.error("Failed to publish alert to SNS: %s", sns_err)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Evaluation completed",
            "remediated_count": len(remediated_rules)
        })
    }
