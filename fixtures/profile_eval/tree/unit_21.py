import hashlib
import time
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/r")
def r():
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    acct = request.args.get("a", "")
    tick = str(int(time.time() / 100))
    tok = hashlib.md5((acct + tick).encode()).hexdigest()
    body = "open http://" + host + "/n/" + tok
    return jsonify({"to": acct, "email_body": body})
