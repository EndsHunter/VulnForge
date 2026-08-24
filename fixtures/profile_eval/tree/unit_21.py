from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/r")
def r():
    host = request.headers.get("Host", "")
    acct = request.args.get("a", "")
    body = "open http://" + host + "/n/" + acct
    return jsonify({"to": acct, "email_body": body})
