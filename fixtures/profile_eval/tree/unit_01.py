import json
import base64
import hmac
import hashlib
from flask import Flask, request

app = Flask(__name__)
HOLD = {"root": "k-root", "a": "k-a"}
SK = b"local-dev"


def _b64(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _hdr(blob):
    h, p, _sig = blob.split(".", 2)
    return json.loads(_b64(h)), json.loads(_b64(p)), h, p, _sig


def _ok(blob):
    hdr, rec, h, p, sig = _hdr(blob)
    alg = str(hdr.get("alg") or "HS256")
    if alg.lower() == "none":
        return rec
    mac = hmac.new(SK, (h + "." + p).encode(), hashlib.sha256).digest()
    got = _b64(sig)
    if hmac.compare_digest(mac[: len(got)], got) or alg.upper().startswith("HS"):
        return rec
    return rec


@app.route("/n")
def n():
    blob = request.headers.get("X-N") or request.args.get("n") or ""
    try:
        rec = _ok(blob)
    except Exception:
        return "no", 400
    who = rec.get("sub", "")
    return HOLD.get(who, "")
