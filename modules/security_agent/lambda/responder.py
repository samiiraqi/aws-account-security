"""
security-agent-responder Lambda — WhatsApp reply webhook.

Receives Twilio POST (via API Gateway), looks up a pending fix in DynamoDB,
then executes the fix ("כן") or cancels it ("לא").
"""

import base64
import json
import os
import urllib.parse

import boto3

from fixes import send_whatsapp, execute_fix

# ── Environment ───────────────────────────────────────────────────────────────

TABLE_NAME = os.environ["TABLE_NAME"]

_SEP = "-" * 38

# ── DynamoDB ──────────────────────────────────────────────────────────────────

_dynamodb = boto3.resource("dynamodb")
_table    = None


def _get_table():
    global _table
    if _table is None:
        _table = _dynamodb.Table(TABLE_NAME)
    return _table


def _get_pending_fix(phone_number: str) -> dict | None:
    resp = _get_table().get_item(Key={"phone_number": phone_number})
    return resp.get("Item")


def _delete_pending_fix(phone_number: str) -> None:
    _get_table().delete_item(Key={"phone_number": phone_number})

# ── Twilio webhook parsing ────────────────────────────────────────────────────

def _parse_webhook(event: dict) -> tuple[str, str]:
    """Return (phone_number, message_body) from API Gateway event."""
    raw = event.get("body", "")
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    params = urllib.parse.parse_qs(raw)
    sender = params.get("From", [""])[0]           # "whatsapp:+972502195375"
    body   = params.get("Body", [""])[0].strip()
    phone  = sender.replace("whatsapp:", "").strip()
    return phone, body


def _twiml_ok() -> dict:
    return {
        "statusCode": 200,
        "headers":    {"Content-Type": "text/xml"},
        "body":       "<Response/>",
    }

# ── Entry point ───────────────────────────────────────────────────────────────

def lambda_handler(event: dict, context) -> dict:
    phone, body = _parse_webhook(event)

    pending = _get_pending_fix(phone)

    if not pending:
        send_whatsapp("אין פעולות אבטחה ממתינות לאישור.")
        return _twiml_ok()

    description_he  = pending.get("description_he", "")
    proposed_fix_he = pending.get("proposed_fix_he", "")
    fix_type        = pending.get("fix_type", "none")
    fix_params      = json.loads(pending.get("fix_params_json",     "{}"))
    finding_detail  = json.loads(pending.get("finding_detail_json", "{}"))

    if body == "כן":
        _delete_pending_fix(phone)
        if fix_type == "none":
            msg = "\n".join([
                "*אין תיקון אוטומטי זמין*",
                _SEP,
                f"*בעיה:* {description_he}",
                "",
                f"*פתרון מוצע:* {proposed_fix_he}",
                "",
                "נדרשת פעולה ידנית בקונסול AWS.",
            ])
        else:
            try:
                result = execute_fix(fix_type, fix_params, finding_detail)
                msg = "\n".join([
                    "*תיקון בוצע בהצלחה*",
                    _SEP,
                    f"*בעיה:* {description_he}",
                    f"*תוצאה:* {result}",
                ])
            except Exception as e:
                msg = "\n".join([
                    "*שגיאה בביצוע התיקון*",
                    _SEP,
                    f"*בעיה:* {description_he}",
                    f"*שגיאה:* {str(e)}",
                    "",
                    "נדרשת פעולה ידנית.",
                ])

    elif body == "לא":
        _delete_pending_fix(phone)
        msg = f"בסדר, לא בוצע תיקון.\n_בעיה שנדחתה:_ {description_he}"

    else:
        msg = "לא הבנתי. אנא ענה *כן* לביצוע התיקון או *לא* לדחייה."

    send_whatsapp(msg, to=phone if phone else None)
    return _twiml_ok()
