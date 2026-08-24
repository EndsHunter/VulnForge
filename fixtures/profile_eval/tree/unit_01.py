import json
import base64
from flask import Flask, request

app = Flask(__name__)
STORE = {"admin": "k-admin", "a": "k-a"}


def _mid(blob):
    part = blob.split(".")[1]
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))


@app.route("/n")
def n():
    blob = request.headers.get("X-N") or request.args.get("n") or ""
    try:
        rec = _mid(blob)
    except Exception:
        return "no", 400
    who = rec.get("sub", "")
    return STORE.get(who, "")
