"""Shared utilities: Twilio sender and boto3 fix executors."""

import base64
import json
import os
import re
import urllib.parse
import urllib.request

import boto3

# ── AWS clients ───────────────────────────────────────────────────────────────

secretsmanager = boto3.client("secretsmanager")
ec2_client     = boto3.client("ec2")
iam_client     = boto3.client("iam")
s3_client      = boto3.client("s3")

# ── Environment ───────────────────────────────────────────────────────────────

TWILIO_SECRET_ARN = os.environ["TWILIO_SECRET_ARN"]
WHATSAPP_FROM     = os.environ["WHATSAPP_FROM"]
WHATSAPP_TO       = os.environ["WHATSAPP_TO"]

_twilio_creds: dict | None = None

# Matches all AWS access key ID formats (AKIA*, ASIA*, AROA*, AIDA*, ANPA*)
_AWS_KEY_RE = re.compile(r'\b(?:AKIA|ASIA|AROA|AIDA|ANPA)[A-Z0-9]{16}\b')


def _sanitize(text: str) -> str:
    """Mask any AWS access key IDs in outbound WhatsApp text."""
    return _AWS_KEY_RE.sub("****", text)


def _get_twilio_creds() -> dict:
    global _twilio_creds
    if _twilio_creds is None:
        secret = secretsmanager.get_secret_value(SecretId=TWILIO_SECRET_ARN)
        _twilio_creds = json.loads(secret["SecretString"])
    return _twilio_creds


def send_whatsapp(body: str, to: str | None = None) -> None:
    creds       = _get_twilio_creds()
    account_sid = creds["account_sid"]
    auth_token  = creds["auth_token"]

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    payload = urllib.parse.urlencode({
        "From": f"whatsapp:{WHATSAPP_FROM}",
        "To":   f"whatsapp:{to or WHATSAPP_TO}",
        "Body": _sanitize(body),
    }).encode()

    token = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Basic {token}",
            "Content-Type":  "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req) as resp:
        resp.read()

# ── Fix executors ─────────────────────────────────────────────────────────────

def fix_close_sg_port(detail: dict, params: dict) -> str:
    instance_id = (
        detail.get("resource", {})
              .get("instanceDetails", {})
              .get("instanceId")
    )
    port     = int(params.get("port", 22))
    protocol = params.get("protocol", "tcp")

    resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    sg_ids = [
        sg["GroupId"]
        for r    in resp["Reservations"]
        for inst in r["Instances"]
        for sg   in inst["SecurityGroups"]
    ]

    revoked = []
    for sg_id in sg_ids:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        for rule in sg.get("IpPermissions", []):
            from_p = rule.get("FromPort", 0)
            to_p   = rule.get("ToPort",   0)
            if rule.get("IpProtocol") != protocol or not (from_p <= port <= to_p):
                continue

            open_v4 = [r for r in rule.get("IpRanges",   []) if r.get("CidrIp")   == "0.0.0.0/0"]
            open_v6 = [r for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
            if not open_v4 and not open_v6:
                continue

            ip_perm: dict = {"IpProtocol": protocol, "FromPort": from_p, "ToPort": to_p}
            if open_v4:
                ip_perm["IpRanges"] = open_v4
            if open_v6:
                ip_perm["Ipv6Ranges"] = open_v6

            ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[ip_perm])
            revoked.append(sg_id)

    return (
        f"פורט {port} נסגר ב: {', '.join(revoked)}"
        if revoked else
        f"לא נמצאו כללים פתוחים לציבור לפורט {port}"
    )


def _mask_key(key_id: str) -> str:
    return "****"


def fix_revoke_iam(detail: dict, params: dict) -> str:
    key_info      = detail.get("resource", {}).get("accessKeyDetails", {})
    user_name     = params.get("user_name")     or key_info.get("userName",    "")
    access_key_id = params.get("access_key_id") or key_info.get("accessKeyId", "")

    iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    return f"מפתח גישה {_mask_key(access_key_id)} של {user_name} נמחק"


def fix_block_s3_public(detail: dict, params: dict) -> str:
    buckets     = detail.get("resource", {}).get("s3BucketDetails", [])
    bucket_name = params.get("bucket_name") or (buckets[0]["name"] if buckets else None)
    if not bucket_name:
        raise ValueError("שם ה-bucket חסר בממצא")

    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls":       True,
            "IgnorePublicAcls":      True,
            "BlockPublicPolicy":     True,
            "RestrictPublicBuckets": True,
        },
    )
    return f"גישה ציבורית נחסמה: {bucket_name}"


FIX_HANDLERS = {
    "close_sg_port":   fix_close_sg_port,
    "revoke_iam":      fix_revoke_iam,
    "block_s3_public": fix_block_s3_public,
}


def execute_fix(fix_type: str, fix_params: dict, detail: dict) -> str:
    handler = FIX_HANDLERS.get(fix_type)
    if not handler:
        raise ValueError(f"סוג תיקון לא נתמך: {fix_type}")
    return handler(detail, fix_params)
