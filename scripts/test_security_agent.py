#!/usr/bin/env python3
"""
Invokes the security_agent Lambda directly with a mock GuardDuty finding,
using the exact payload format EventBridge would deliver.

Real AWS resource IDs (EC2 instance, S3 bucket, IAM user) are fetched at
runtime so that Claude's auto-fix actions target actual account resources.

Usage:
    python3 test_security_agent.py                  # default: MEDIUM SSH brute-force
    python3 test_security_agent.py --type backdoor  # Backdoor finding
    python3 test_security_agent.py --type s3        # S3 exfiltration finding
    python3 test_security_agent.py --type iam       # IAM privilege escalation
    python3 test_security_agent.py --severity 8.5   # override severity score
    python3 test_security_agent.py --dry-run        # print payload, don't invoke Lambda
"""

import argparse
import copy
import json
import sys
from datetime import datetime, timezone

import boto3

REGION        = "us-east-1"
ACCOUNT_ID    = "156041402173"
FUNCTION_NAME = "aws-account-security-security-agent"
DETECTOR_ID   = "38cf2feb15352114f51da9dba1d557b8"

_NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ── Real resource fetching ────────────────────────────────────────────────────

def _fetch_ec2_resource() -> dict:
    """Return instanceDetails populated with a real EC2 instance and its SGs."""
    ec2 = boto3.client("ec2", region_name=REGION)
    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}],
    )
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            name = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                inst["InstanceId"],
            )
            return {
                "instanceId":   inst["InstanceId"],
                "instanceType": inst.get("InstanceType", "t3.micro"),
                "tags": [{"key": "Name", "value": name}],
                "networkInterfaces": [{
                    "securityGroups": [
                        {"groupId": sg["GroupId"], "groupName": sg["GroupName"]}
                        for sg in inst.get("SecurityGroups", [])
                    ]
                }],
            }
    return None


def _fetch_s3_resource() -> dict | None:
    """Return s3BucketDetails for the first bucket in the account."""
    s3 = boto3.client("s3", region_name=REGION)
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return None
    name = buckets[0]["Name"]
    return {
        "name": name,
        "type": "Destination",
        "arn":  f"arn:aws:s3:::{name}",
    }


def _fetch_iam_resource() -> dict | None:
    """Return accessKeyDetails for the first IAM user that has an active key."""
    iam = boto3.client("iam")
    for user in iam.list_users(MaxItems=20).get("Users", []):
        uname = user["UserName"]
        keys  = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
        active = [k for k in keys if k["Status"] == "Active"]
        if active:
            return {
                "accessKeyId": active[0]["AccessKeyId"],
                "userName":    uname,
                "userType":    "IAMUser",
                "principalId": user.get("UserId", ""),
            }
    return None


def _fetch_resources(finding_type: str) -> dict:
    """
    Fetch real AWS resources relevant to the given finding type.
    Returns a dict with whatever was found; prints status for each lookup.
    """
    results = {}
    lookups = {}

    if finding_type in ("ssh", "backdoor"):
        lookups["ec2"] = ("EC2 instance ", _fetch_ec2_resource)
    if finding_type == "s3":
        lookups["s3"]  = ("S3 bucket    ", _fetch_s3_resource)
    if finding_type == "iam":
        lookups["iam"] = ("IAM user     ", _fetch_iam_resource)

    if not lookups:
        return results

    print("Fetching real AWS resources...")
    for key, (label, fn) in lookups.items():
        try:
            data = fn()
            if data:
                results[key] = data
                if key == "ec2":
                    sgs = data.get("networkInterfaces", [{}])[0].get("securityGroups", [])
                    sg_str = ", ".join(sg["groupId"] for sg in sgs) or "no SGs"
                    print(f"  {label}: {data['instanceId']} ({data['instanceType']})  SGs: {sg_str}")
                elif key == "s3":
                    print(f"  {label}: {data['name']}")
                elif key == "iam":
                    print(f"  {label}: {data['userName']}  key: {data['accessKeyId']}")
            else:
                print(f"  {label}: none found — using placeholder")
        except Exception as e:
            print(f"  {label}: lookup failed ({e}) — using placeholder")
    print()

    return results


# ── Finding templates ─────────────────────────────────────────────────────────

def _base_event(finding_type: str, title: str, description: str,
                severity: float, resource: dict) -> dict:
    return {
        "version": "0",
        "id":      "test-event-00000000-0000-0000-0000-000000000001",
        "source":  "aws.guardduty",
        "account": ACCOUNT_ID,
        "time":    _NOW,
        "region":  REGION,
        "detail-type": "GuardDuty Finding",
        "detail": {
            "schemaVersion": "2.0",
            "accountId":     ACCOUNT_ID,
            "region":        REGION,
            "type":          finding_type,
            "title":         title,
            "description":   description,
            "severity":      severity,
            "id":            "test-finding-abcdef1234567890abcdef1234567890",
            "createdAt":     _NOW,
            "updatedAt":     _NOW,
            "resource":      resource,
            "service": {
                "detectorId":     DETECTOR_ID,
                "count":          7,
                "eventFirstSeen": _NOW,
                "eventLastSeen":  _NOW,
                "action": {
                    "actionType": "NETWORK_CONNECTION",
                    "networkConnectionAction": {
                        "connectionDirection": "INBOUND",
                        "remoteIpDetails": {
                            "ipAddressV4": "198.51.100.77",
                            "country": {"countryName": "Unknown"},
                            "city":    {"cityName": "Unknown"},
                        },
                        "remotePortDetails": {"port": 22, "portName": "SSH"},
                        "localPortDetails":  {"port": 22, "portName": "SSH"},
                        "protocol": "TCP",
                        "blocked":  False,
                    },
                },
            },
        },
    }


PRESETS = {
    "ssh": _base_event(
        finding_type = "UnauthorizedAccess:EC2/SSHBruteForce",
        title        = "SSH brute force attacks from 198.51.100.77",
        description  = (
            "198.51.100.77 is performing SSH brute force attacks against i-0abc123def456. "
            "Brute force attacks are used to gain unauthorized access to your instance "
            "by guessing the SSH password."
        ),
        severity = 2.0,
        resource = {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId":   "i-0abc123def456",
                "instanceType": "t3.micro",
                "tags": [{"key": "Name", "value": "web-server-01"}],
                "networkInterfaces": [],
            },
        },
    ),
    "backdoor": _base_event(
        finding_type = "Backdoor:EC2/C&CActivity.B",
        title        = "Command and Control server communication",
        description  = (
            "EC2 instance i-0abc123def456 is communicating with a known C&C server "
            "associated with malware activity."
        ),
        severity = 7.8,
        resource = {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId":   "i-0abc123def456",
                "instanceType": "t3.medium",
                "tags": [{"key": "Name", "value": "app-server-prod"}],
                "networkInterfaces": [],
            },
        },
    ),
    "s3": _base_event(
        finding_type = "Exfiltration:S3/ObjectRead.Unusual",
        title        = "Unusual S3 object read activity",
        description  = (
            "An unusual number of S3 API calls were made by user john.doe. "
            "This activity is unusual for this user."
        ),
        severity = 8.0,
        resource = {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{
                "name": "aws-account-security-cloudtrail-156041402173",
                "type": "Destination",
                "arn":  "arn:aws:s3:::aws-account-security-cloudtrail-156041402173",
            }],
        },
    ),
    "iam": _base_event(
        finding_type = "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        title        = "An IAM user invoked an API commonly used for privilege escalation",
        description  = (
            "IAM user john.doe called iam:AttachUserPolicy with an administrator policy, "
            "which is anomalous activity for this user."
        ),
        severity = 8.9,
        resource = {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName":    "john.doe",
                "userType":    "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            },
        },
    ),
}


# ── Patch preset with real resources ─────────────────────────────────────────

def _apply_real_resources(event: dict, finding_type: str, resources: dict) -> None:
    """Mutate a deep-copied event with real resource IDs in-place."""
    detail = event["detail"]

    if finding_type in ("ssh", "backdoor") and "ec2" in resources:
        detail["resource"]["instanceDetails"] = resources["ec2"]
        inst_id = resources["ec2"]["instanceId"]
        detail["title"]       = detail["title"].replace("i-0abc123def456", inst_id)
        detail["description"] = detail["description"].replace("i-0abc123def456", inst_id)

    if finding_type == "s3" and "s3" in resources:
        detail["resource"]["s3BucketDetails"][0] = resources["s3"]

    if finding_type == "iam" and "iam" in resources:
        detail["resource"]["accessKeyDetails"].update(resources["iam"])
        uname = resources["iam"]["userName"]
        detail["title"]       = detail["title"].replace("john.doe", uname)
        detail["description"] = detail["description"].replace("john.doe", uname)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Test security_agent Lambda")
    parser.add_argument(
        "--type",
        choices=list(PRESETS),
        default="ssh",
        help="Finding preset to send (default: ssh)",
    )
    parser.add_argument(
        "--severity",
        type=float,
        default=None,
        help="Override the severity score (e.g. 9.0 for CRITICAL)",
    )
    parser.add_argument(
        "--function",
        default=FUNCTION_NAME,
        help=f"Lambda function name (default: {FUNCTION_NAME})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the payload without invoking the Lambda",
    )
    args = parser.parse_args()

    resources = _fetch_resources(args.type)

    event = copy.deepcopy(PRESETS[args.type])
    _apply_real_resources(event, args.type, resources)

    if args.severity is not None:
        event["detail"]["severity"] = args.severity

    detail = event["detail"]
    print(f"Function : {args.function}")
    print(f"Type     : {detail['type']}")
    print(f"Severity : {detail['severity']}")
    print(f"Resource : {detail['resource']['resourceType']}")
    print()

    if args.dry_run:
        print("--- Payload (dry run) ---")
        print(json.dumps(event, indent=2, ensure_ascii=False))
        return

    client   = boto3.client("lambda", region_name=REGION)
    response = client.invoke(
        FunctionName   = args.function,
        InvocationType = "RequestResponse",
        Payload        = json.dumps(event).encode(),
    )

    status_code = response["StatusCode"]
    payload     = json.loads(response["Payload"].read())

    if response.get("FunctionError"):
        print(f"FAILED  ({response['FunctionError']})")
        print(json.dumps(payload, indent=2))
        sys.exit(1)

    print(f"Status  : {status_code}")
    print(f"Result  : {json.dumps(payload, indent=2)}")
    print()
    print("WhatsApp message sent successfully.")


if __name__ == "__main__":
    main()
