from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
eng = create_engine("sqlite:///data.db")


@app.post("/q")
def q():
    name = request.form.get("n", "")
    with eng.connect() as c:
        c.execute(text("SELECT * FROM items WHERE label LIKE " + name))
    return "ok"
