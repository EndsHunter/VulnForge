import hashlib
from Crypto.Cipher import AES
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "x"
K = b"Sixteen byte key"
IV = b"\x00" * 16


def _pad(raw):
    n = 16 - (len(raw) % 16)
    return raw + bytes([n]) * n


def put(msg):
    c = AES.new(K, AES.MODE_CBC, IV)
    return c.encrypt(_pad(msg.encode()))


def get(blob):
    c = AES.new(K, AES.MODE_CBC, IV)
    out = c.decrypt(blob)
    return out[: -out[-1]].decode()


@app.post("/in")
def inn():
    pw = request.form.get("p", "")
    session["h"] = hashlib.md5(pw.encode()).hexdigest()
    return put(pw)


@app.post("/out")
def out():
    return get(request.get_data())
