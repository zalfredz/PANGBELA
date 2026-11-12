"""Approved maintenance operation. Signs one request with the lab secret so the app can
record it as an approved operation; the Suricata alert it triggers is then a true
false-positive case.

    python maintenance.py            # one signed request
    python maintenance.py --forged   # wrong secret, must be refused
    python maintenance.py --replay   # same signature twice, second must be refused
"""

import hashlib
import hmac
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

APP = os.environ.get("APP_BASE", "http://app:8080")
SECRET = os.environ.get("LAB_APPROVAL_SECRET", "")
PATH = "/vuln/ping?host=127.0.0.1%3B%20printf%20LAB_RCE_OK"


def header(secret: str) -> str:
    ts, nonce = str(int(time.time())), uuid.uuid4().hex
    mac = hmac.new(secret.encode(), f"{ts}:{nonce}:{PATH}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def send(value: str) -> int:
    req = urllib.request.Request(f"{APP}{PATH}", headers={"X-Lab-Approval": value})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--forged":
        print("forged", send(header(SECRET + "-wrong")))
    elif mode == "--replay":
        value = header(SECRET)
        print("replay", send(value), send(value))
    else:
        print("approved", send(header(SECRET)))
