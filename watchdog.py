#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


INTEGRITY_URL = os.environ.get("INTEGRITY_URL", "https://xynote.de/api/integrity")
HOME_URL = os.environ.get("HOME_URL", "https://xynote.de/")
EXPECTED_FINGERPRINT = os.environ.get(
    "EXPECTED_FINGERPRINT",
    "SHA256:Cjz/qrgq22L96iU6HlJq28ePXhz9PGIGveMcHnganDs",
)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


def fetch(url, timeout=20):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "cipher-integrity-watchdog/1.0",
            "Accept": "application/json,text/html,*/*",
        },
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return response.status, dict(response.headers), body, elapsed_ms


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram secrets are not configured; alert not sent.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status >= 300:
            raise RuntimeError(f"Telegram returned HTTP {response.status}")


def fail(message, details):
    alert = "Cipher Watchdog ALERT\n\n" + message
    if details:
        alert += "\n\n" + details
    send_telegram(alert[:3900])
    print(alert)
    sys.exit(1)


def main():
    try:
        status, headers, body, elapsed_ms = fetch(INTEGRITY_URL)
    except (urllib.error.URLError, TimeoutError) as exc:
        fail("Integrity endpoint is not reachable.", f"{INTEGRITY_URL}\n{exc}")

    if status != 200:
        fail("Integrity endpoint returned a bad HTTP status.", f"HTTP {status}")

    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        fail("Integrity endpoint did not return valid JSON.", str(exc))

    problems = []
    if data.get("ok") is not True:
        problems.append("overall ok=false")
    if data.get("filesOk") is not True:
        problems.append("filesOk=false")
    if data.get("dnsOk") is not True:
        problems.append("dnsOk=false")

    public_fingerprint = data.get("publicKeyFingerprint", "")
    dns_fingerprint = data.get("dnsFingerprint", "")
    if public_fingerprint != EXPECTED_FINGERPRINT:
        problems.append(f"publicKeyFingerprint mismatch: {public_fingerprint}")
    if dns_fingerprint != EXPECTED_FINGERPRINT:
        problems.append(f"dnsFingerprint mismatch: {dns_fingerprint}")

    changed_files = [
        item.get("path", "unknown")
        for item in data.get("files", [])
        if item.get("ok") is not True
    ]
    if changed_files:
        problems.append("changed files: " + ", ".join(changed_files))

    try:
        home_status, _, _, home_elapsed_ms = fetch(HOME_URL)
    except (urllib.error.URLError, TimeoutError) as exc:
        problems.append(f"home page unreachable: {exc}")
        home_status = "error"
        home_elapsed_ms = 0

    if home_status != 200:
        problems.append(f"home page HTTP status: {home_status}")

    if problems:
        fail(
            "Cipher integrity check failed.",
            "\n".join(
                [
                    f"integrity_url={INTEGRITY_URL}",
                    f"integrity_http={status}",
                    f"integrity_ms={elapsed_ms}",
                    f"home_url={HOME_URL}",
                    f"home_http={home_status}",
                    f"home_ms={home_elapsed_ms}",
                    f"created_at={data.get('createdAt', '')}",
                    "",
                    "Problems:",
                    *problems,
                ]
            ),
        )

    print("Cipher integrity OK")
    print(f"integrity_ms={elapsed_ms}")
    print(f"home_ms={home_elapsed_ms}")
    print(f"created_at={data.get('createdAt', '')}")


if __name__ == "__main__":
    main()
