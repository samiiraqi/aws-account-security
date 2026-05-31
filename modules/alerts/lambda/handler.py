import os
import boto3
from datetime import datetime
from urllib.parse import quote

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

_SEP = "-" * 60

_SEVERITY_PREFIX = {
    "CRITICAL": "[!!!] CRITICAL",
    "HIGH":     "[!!]  HIGH",
    "MEDIUM":   "[!]   MEDIUM",
    "LOW":      "[-]   LOW",
}


def _fmt_time(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_str or "Unknown"


def _parse_guardduty(detail: dict) -> dict:
    score = float(detail.get("severity", 0))
    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    finding_id = detail.get("id", "")
    region = detail.get("region", os.environ.get("AWS_REGION", "us-east-1"))
    console_url = (
        f"https://{region}.console.aws.amazon.com/guardduty/home"
        f"?region={region}#/findings?search=id%3D{finding_id}"
    )
    return {
        "service":     "GuardDuty",
        "title":       detail.get("title", "Unknown Finding"),
        "description": detail.get("description", "No description provided."),
        "severity":    severity,
        "account_id":  detail.get("accountId", "Unknown"),
        "region":      region,
        "time":        _fmt_time(detail.get("createdAt", "")),
        "console_url": console_url,
    }


def _parse_securityhub(detail: dict) -> dict:
    findings = detail.get("findings", [])
    if not findings:
        raise ValueError("Security Hub event contains no findings")

    finding = findings[0]
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    finding_id = finding.get("Id", "")
    region = finding.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
    console_url = (
        f"https://{region}.console.aws.amazon.com/securityhub/home"
        f"?region={region}#/findings?search=Id%3D{quote(finding_id, safe='')}"
    )
    return {
        "service":     "Security Hub",
        "title":       finding.get("Title", "Unknown Finding"),
        "description": finding.get("Description", "No description provided."),
        "severity":    severity,
        "account_id":  finding.get("AwsAccountId", "Unknown"),
        "region":      region,
        "time":        _fmt_time(finding.get("CreatedAt", "")),
        "console_url": console_url,
    }


def _build_email(data: dict) -> tuple[str, str]:
    prefix = _SEVERITY_PREFIX.get(data["severity"], f"[?]   {data['severity']}")
    subject = f"{prefix} | {data['service']}: {data['title']}"[:100]

    body = "\n".join([
        f"AWS SECURITY ALERT — {data['service']}",
        _SEP,
        f"Severity    : {data['severity']}",
        f"Service     : {data['service']}",
        f"Account     : {data['account_id']}",
        f"Region      : {data['region']}",
        f"Time        : {data['time']}",
        "",
        "Problem:",
        f"  {data['title']}",
        "",
        "Details:",
        f"  {data['description']}",
        "",
        _SEP,
        "Remediate in the AWS Console:",
        f"  {data['console_url']}",
        _SEP,
    ])
    return subject, body


def lambda_handler(event: dict, context) -> dict:
    source = event.get("source", "")

    if source == "aws.guardduty":
        data = _parse_guardduty(event.get("detail", {}))
    elif source == "aws.securityhub":
        data = _parse_securityhub(event.get("detail", {}))
    else:
        raise ValueError(f"Unsupported event source: {source!r}")

    subject, body = _build_email(data)
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)

    return {"statusCode": 200, "message": f"Alert published: {subject}"}
