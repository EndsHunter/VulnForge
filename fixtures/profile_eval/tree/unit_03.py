from Crypto.Cipher import AES
from flask import Flask, request

app = Flask(__name__)
K = b"Sixteen byte key"


def a(msg):
    c = AES.new(K, AES.MODE_ECB)
    raw = msg.encode()
    raw += b" " * ((16 - len(raw) % 16) % 16)
    return c.encrypt(raw)


def b(blob):
    c = AES.new(K, AES.MODE_ECB)
    return c.decrypt(blob).rstrip().decode()


@app.post("/c")
def c():
    return a(request.form.get("m", ""))
