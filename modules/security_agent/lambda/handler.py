"""
security_agent Lambda — GuardDuty finding analyzer and auto-remediation.

Flow:
  1. Parse GuardDuty finding from EventBridge
  2. Fetch Claude API key from Secrets Manager
  3. Ask Claude: auto-fix or needs human approval?
  4a. auto_fix        → execute boto3 remediation → WhatsApp summary
  4b. human_approval  → store in DynamoDB → WhatsApp ask for confirmation
"""

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import boto3

from fixes import send_whatsapp, execute_fix, WHATSAPP_TO

# ── Environment ───────────────────────────────────────────────────────────────

CLAUDE_SECRET_NAME = os.environ["CLAUDE_SECRET_NAME"]
TABLE_NAME         = os.environ["TABLE_NAME"]

_SEP = "-" * 38

# ── Module-level caches ───────────────────────────────────────────────────────

_secretsmanager  = boto3.client("secretsmanager")
_dynamodb        = boto3.resource("dynamodb")
_claude_api_key: str | None = None
_ddb_table                  = None

# ── Hebrew labels ─────────────────────────────────────────────────────────────

_SEVERITY_HE = {
    "CRITICAL": "קריטי",
    "HIGH":     "גבוה",
    "MEDIUM":   "בינוני",
    "LOW":      "נמוך",
}

_FINDING_MAP: dict[str, tuple[str, str]] = {
    "Backdoor":            ("דלת אחורית זוהתה",         "בודד את ה-instance מיידית ובצע forensics"),
    "Behavior":            ("התנהגות חשודה",             "בחן לוגים וודא שהמשתמש מורשה"),
    "CryptoCurrency":      ("כריית מטבעות דיגיטליים",   "עצור את ה-instance ובדוק תהליכים רצים"),
    "DefenseEvasion":      ("עקיפת מנגנוני הגנה",        "בדוק שינויים ב-CloudTrail וב-Config"),
    "Discovery":           ("סיור ומיפוי הסביבה",        "בדוק ניסיונות גישה חריגים ל-APIs"),
    "Exfiltration":        ("ניסיון דליפת מידע",         "בחן S3 bucket policies וגישות לנתונים רגישים"),
    "Impact":              ("פגיעה במשאבים",             "בדוק שלמות נתונים ושקול שחזור מגיבוי"),
    "InitialAccess":       ("כניסה ראשונית לסביבה",      "שנה סיסמאות ומפתחות, בדוק IAM"),
    "PenTest":             ("בדיקת חדירה זוהתה",         "ודא שמדובר בבדיקה מורשית"),
    "Persistence":         ("ניסיון שמירת גישה",         "בדוק IAM roles חדשים ומשימות מתוזמנות"),
    "Policy":              ("הפרת מדיניות אבטחה",        "עדכן S3 policies והגבל גישה ציבורית"),
    "PrivilegeEscalation": ("העלאת הרשאות",              "בטל הרשאות חשודות ובדוק IAM role assumptions"),
    "Recon":               ("סיור ומיפוי רשת",           "בדוק ניסיונות port scanning וחסום IPs חשודים"),
    "Stealth":             ("הסתרת פעילות",              "בחן שינויים ב-logging ו-monitoring"),
    "Trojan":              ("קוד זדוני זוהה",            "בודד instance מיידית ובדוק את הקוד הרץ"),
    "UnauthorizedAccess":  ("גישה לא מורשית",            "חסום IP חשוד ועדכן Security Groups"),
}
_DEFAULT_FINDING = ("פעילות חשודה זוהתה", "בחן את הממצא בקונסול AWS ופעל בהתאם")

# ── Secret fetching ───────────────────────────────────────────────────────────

def _get_claude_api_key() -> str:
    global _claude_api_key
    if _claude_api_key is None:
        print(f"[secret] fetching {CLAUDE_SECRET_NAME!r}")
        secret        = _secretsmanager.get_secret_value(SecretId=CLAUDE_SECRET_NAME)
        secret_string = secret["SecretString"]
        print(f"[secret] fetched ok  length={len(secret_string)}  preview={secret_string[:20]!r}")
        try:
            _claude_api_key = json.loads(secret_string)["api_key"]
            print(f"[secret] API key parsed from JSON  prefix={_claude_api_key[:12]!r}")
        except (json.JSONDecodeError, KeyError):
            _claude_api_key = secret_string.strip()
            print(f"[secret] API key used as raw string  prefix={_claude_api_key[:12]!r}")
    return _claude_api_key

# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity(score: float) -> tuple[str, str]:
    if score >= 9.0:
        return "CRITICAL", _SEVERITY_HE["CRITICAL"]
    if score >= 7.0:
        return "HIGH", _SEVERITY_HE["HIGH"]
    if score >= 4.0:
        return "MEDIUM", _SEVERITY_HE["MEDIUM"]
    return "LOW", _SEVERITY_HE["LOW"]


def _extract_resource(resource: dict) -> str:
    rtype = resource.get("resourceType", "")
    if rtype == "Instance":
        d = resource.get("instanceDetails", {})
        return f"EC2 Instance: {d.get('instanceId', '?')} ({d.get('instanceType', '?')})"
    if rtype == "S3Bucket":
        buckets = resource.get("s3BucketDetails", [])
        return f"S3 Bucket: {buckets[0].get('name', '?')}" if buckets else "S3 Bucket"
    if rtype == "AccessKey":
        d      = resource.get("accessKeyDetails", {})
        raw_id = d.get("accessKeyId", "?")
        masked = "****"
        return f"IAM User: {d.get('userName', '?')} (key: {masked})"
    if rtype == "EKSCluster":
        return f"EKS Cluster: {resource.get('eksClusterDetails', {}).get('name', '?')}"
    if rtype == "Lambda":
        return f"Lambda: {resource.get('lambdaDetails', {}).get('functionName', '?')}"
    if rtype == "RDSDBInstance":
        return f"RDS: {resource.get('rdsDbInstanceDetails', {}).get('dbInstanceIdentifier', '?')}"
    return rtype or "לא ידוע"


def _fmt_time(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        return iso_str or "לא ידוע"


def _console_url(detail: dict) -> str:
    region     = detail.get("region", "us-east-1")
    finding_id = detail.get("id", "")
    return (
        f"https://{region}.console.aws.amazon.com/guardduty/home"
        f"?region={region}#/findings?search=id%3D{finding_id}"
    )

# ── Claude analysis ───────────────────────────────────────────────────────────

_PROMPT_TEMPLATE = """\
You are an AWS security expert. Analyze this GuardDuty finding and decide the best action.

Finding:
- Type        : {finding_type}
- Title       : {title}
- Severity    : {severity} / 10
- Resource    : {resource}
- Region      : {region}
- Description : {description}

Resource JSON:
{resource_json}

Reply with ONLY a valid JSON object — no markdown, no explanation.

auto_fix: safe, reversible, well-understood fixes that can run immediately.
human_approval: risky changes, malware/backdoors, or anything needing confirmation.
  Always include fix_type and fix_params even for human_approval so the fix can execute after approval.

auto_fix schema (pick one fix_type):
{{
  "action": "auto_fix",
  "fix_type": "close_sg_port" | "revoke_iam" | "block_s3_public",
  "fix_params": {{
    // close_sg_port   → {{"port": 22, "protocol": "tcp"}}
    // revoke_iam      → {{"user_name": "...", "access_key_id": "..."}}
    // block_s3_public → {{"bucket_name": "..."}}
  }},
  "description_he": "תיאור קצר של הבעיה בעברית",
  "action_taken_he": "תיאור הפעולה שתתבצע בעברית"
}}

human_approval schema:
{{
  "action": "human_approval",
  "fix_type": "close_sg_port" | "revoke_iam" | "block_s3_public" | "none",
  "fix_params": {{
    // same structure as auto_fix, or {{}} if fix_type is "none"
  }},
  "description_he": "תיאור קצר של הבעיה בעברית",
  "proposed_fix_he": "הפתרון המוצע בעברית"
}}

Auto-fix rules:
- SSH/RDP brute force on EC2 → auto_fix → close_sg_port (port from finding)
- S3 bucket made public      → auto_fix → block_s3_public
- Compromised IAM access key → auto_fix → revoke_iam
- Backdoor / malware / C&C   → human_approval with appropriate fix_type and params
- Everything else             → human_approval with fix_type="none"\
"""


def _analyze_with_claude(detail: dict) -> dict:
    finding_type = detail.get("type", "")
    severity     = detail.get("severity", 0)

    print(f"[claude] sending finding  type={finding_type!r}  severity={severity}")

    prompt = _PROMPT_TEMPLATE.format(
        finding_type  = finding_type,
        title         = detail.get("title", ""),
        severity      = severity,
        resource      = _extract_resource(detail.get("resource", {})),
        region        = detail.get("region", ""),
        description   = detail.get("description", ""),
        resource_json = json.dumps(detail.get("resource", {}), indent=2),
    )

    body = json.dumps({
        "model":      "claude-haiku-4-5-20251001",
        "max_tokens": 512,
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key":         _get_claude_api_key(),
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status   = resp.status
            raw_body = resp.read()
    except urllib.error.HTTPError as e:
        status   = e.code
        raw_body = e.read()
        print(f"[claude] HTTP error  status={status}  body={raw_body.decode('utf-8', errors='replace')!r}")
        raise

    print(f"[claude] HTTP status={status}  body_length={len(raw_body)}")
    print(f"[claude] raw body: {raw_body.decode('utf-8', errors='replace')}")

    response = json.loads(raw_body)
    print(f"[claude] parsed response: {json.dumps(response, ensure_ascii=False)}")

    raw = response["content"][0]["text"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    decision = json.loads(raw)
    print(f"[claude] decision: {json.dumps(decision, ensure_ascii=False)}")
    return decision

# ── DynamoDB pending-fix storage ──────────────────────────────────────────────

def _get_table():
    global _ddb_table
    if _ddb_table is None:
        _ddb_table = _dynamodb.Table(TABLE_NAME)
    return _ddb_table


def _store_pending_fix(decision: dict, detail: dict) -> None:
    _get_table().put_item(Item={
        "phone_number":        WHATSAPP_TO,
        "fix_type":            decision.get("fix_type", "none"),
        "fix_params_json":     json.dumps(decision.get("fix_params", {})),
        "description_he":      decision.get("description_he", ""),
        "proposed_fix_he":     decision.get("proposed_fix_he", ""),
        "finding_detail_json": json.dumps(detail),
        "ttl":                 int(time.time()) + 86400,
    })

# ── Message builders ──────────────────────────────────────────────────────────

def _msg_auto_fix(detail: dict, decision: dict, result: str) -> str:
    _, sev_he = _severity(float(detail.get("severity", 0)))
    return "\n".join([
        "*תוקן אוטומטית*",
        _SEP,
        f"*חומרה:* {sev_he}",
        f"*בעיה:*  {decision.get('description_he', '')}",
        f"*פעולה:* {decision.get('action_taken_he', '')}",
        f"*תוצאה:* {result}",
        f"*זמן:*   {_fmt_time(detail.get('createdAt', ''))}",
        "",
        _SEP,
        f"*קונסול:* {_console_url(detail)}",
    ])


def _msg_approval_request(detail: dict, decision: dict) -> str:
    _, sev_he = _severity(float(detail.get("severity", 0)))
    fix_note = (
        ""
        if decision.get("fix_type", "none") == "none"
        else "\n_תיקון אוטומטי זמין — ממתין לאישורך_"
    )
    return "\n".join([
        "*דרוש אישור — אבטחה*",
        _SEP,
        f"*חומרה:* {sev_he}",
        "",
        "*זוהתה בעיה:*",
        decision.get("description_he", ""),
        "",
        "*פתרון מוצע:*",
        decision.get("proposed_fix_he", ""),
        fix_note,
        "",
        _SEP,
        "רוצה שאתקן? ענה *כן* או *לא*",
    ])


def _msg_fix_failed(detail: dict, decision: dict, error: str) -> str:
    return "\n".join([
        "*שגיאה בתיקון אוטומטי*",
        _SEP,
        f"*בעיה:*  {decision.get('description_he', '')}",
        f"*שגיאה:* {error}",
        "",
        f"בדוק ידנית: {_console_url(detail)}",
    ])

# ── Entry point ───────────────────────────────────────────────────────────────

def lambda_handler(event: dict, context) -> dict:
    detail = event.get("detail", {})

    try:
        decision = _analyze_with_claude(detail)
    except Exception as e:
        print(f"Claude analysis failed: {e}")
        prefix  = detail.get("type", "").split(":")[0]
        desc_he = _FINDING_MAP.get(prefix, _DEFAULT_FINDING)[0]
        decision = {
            "action":          "human_approval",
            "fix_type":        "none",
            "fix_params":      {},
            "description_he":  desc_he,
            "proposed_fix_he": "בחן ידנית בקונסול AWS",
        }

    action = decision.get("action", "human_approval")

    if action == "auto_fix":
        try:
            result = execute_fix(
                decision.get("fix_type", ""),
                decision.get("fix_params", {}),
                detail,
            )
            msg = _msg_auto_fix(detail, decision, result)
        except Exception as e:
            print(f"Auto-fix failed: {e}")
            msg = _msg_fix_failed(detail, decision, str(e))
    else:
        _store_pending_fix(decision, detail)
        msg = _msg_approval_request(detail, decision)

    send_whatsapp(msg)
    return {"statusCode": 200, "action": action}
