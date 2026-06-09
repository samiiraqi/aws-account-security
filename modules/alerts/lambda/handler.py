import base64
import json
import os
import urllib.parse
import urllib.request

import boto3

secretsmanager = boto3.client("secretsmanager")

TWILIO_SECRET_ARN = os.environ["TWILIO_SECRET_ARN"]
WHATSAPP_FROM     = os.environ["WHATSAPP_FROM"]
WHATSAPP_TO       = os.environ["WHATSAPP_TO"]
BUDGET_LIMIT_USD  = os.environ["BUDGET_LIMIT_USD"]

_SEP = "-" * 50

# Cached on first invocation to avoid a Secrets Manager call on every event
_twilio_creds: dict | None = None


def _get_twilio_creds() -> dict:
    global _twilio_creds
    if _twilio_creds is None:
        secret = secretsmanager.get_secret_value(SecretId=TWILIO_SECRET_ARN)
        _twilio_creds = json.loads(secret["SecretString"])
    return _twilio_creds


def _send_whatsapp(body: str) -> None:
    creds = _get_twilio_creds()
    account_sid = creds["account_sid"]
    auth_token  = creds["auth_token"]

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    payload = urllib.parse.urlencode({
        "From": f"whatsapp:{WHATSAPP_FROM}",
        "To":   f"whatsapp:{WHATSAPP_TO}",
        "Body": body,
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


def _build_whatsapp_message(subject: str, sns_message: str) -> str:
    text_lower = (subject + sns_message).lower()
    if "forecast" in text_lower:
        alert_type = "Forecast — approaching limit"
    else:
        alert_type = "Actual cost exceeded limit"

    return "\n".join([
        "*AWS Billing Alert*",
        _SEP,
        f"*Type:*   {alert_type}",
        f"*Budget:* ${BUDGET_LIMIT_USD} / month",
        "",
        sns_message.strip(),
        "",
        _SEP,
        "*View budget:*",
        "https://console.aws.amazon.com/billing/home#/budgets",
    ])


def lambda_handler(event: dict, context) -> dict:
    for record in event.get("Records", []):
        sns     = record.get("Sns", {})
        subject = sns.get("Subject") or "AWS Billing Alert"
        message = sns.get("Message") or subject
        _send_whatsapp(_build_whatsapp_message(subject, message))
    return {"statusCode": 200}
