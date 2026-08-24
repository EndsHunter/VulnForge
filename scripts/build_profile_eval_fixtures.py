#!/usr/bin/env python3
"""Write the frozen 21-class obfuscated hunt-profile eval tree.

Sources are snippets from snoopysecurity/Broken-Vulnerable-Code-Snippets
and NavidNaf/TheDamnVulnerableCodebase, with comments and telltale names
stripped. Re-run to restore the frozen set.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / "fixtures" / "profile_eval" / "tree"
GT = ROOT / "fixtures" / "profile_eval" / "ground_truth.json"

# (id, hunt class, filename, body)
UNITS: list[tuple[str, str, str, str]] = [
    (
        "jwt",
        "web-protocol-auth",
        "unit_01.py",
        '''import json
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
''',
    ),
    (
        "cmd",
        "injection",
        "unit_02.php",
        '''<?php
$q = $_GET["q"] ?? "";
system($q);
''',
    ),
    (
        "crypto",
        "cryptography",
        "unit_03.py",
        '''from Crypto.Cipher import AES
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
''',
    ),
    (
        "upload",
        "feature-abuse",
        "unit_04.php",
        '''<?php
$base = "/var/www/html/store/";
$dest = $base . basename($_FILES["f"]["name"]);
move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
echo $dest;
''',
    ),
    (
        "path",
        "injection",
        "unit_05.php",
        '''<?php
$root = "/var/www/";
$rel = $_GET["p"] ?? "";
$path = $root . $rel;
$h = fopen($path, "rb");
while (!feof($h)) {
    echo fread($h, 8192);
}
fclose($h);
''',
    ),
    (
        "sql",
        "injection",
        "unit_06.py",
        '''from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
eng = create_engine("sqlite:///data.db")


@app.post("/q")
def q():
    name = request.form.get("n", "")
    with eng.connect() as c:
        c.execute(text("SELECT * FROM items WHERE label LIKE " + name))
    return "ok"
''',
    ),
    (
        "sql-err",
        "injection",
        "unit_07.php",
        '''<?php
$sku = $_GET["sku"] ?? "";
$q = "SELECT * FROM items WHERE sku = '" . $sku . "'";
$r = mysql_query($q) or die(mysql_error());
while ($row = mysql_fetch_assoc($r)) {
    echo $row["name"];
}
''',
    ),
    (
        "sql-union",
        "injection",
        "unit_08.php",
        '''<?php
$cat = $_GET["cat"] ?? "";
$db = new SQLite3("store.db");
$q = "SELECT name, price FROM items WHERE cat = '" . $cat . "'";
$r = $db->query($q);
while ($row = $r->fetchArray()) {
    echo $row["name"] . " " . $row["price"];
}
''',
    ),
    (
        "sql-blind",
        "injection",
        "unit_09.php",
        '''<?php
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
$n = $db->querySingle("select count(*) from notes where id = " . $id);
if ($n > 0) {
    echo "Yes!";
} else {
    echo "No!";
}
''',
    ),
    (
        "xss",
        "client-side",
        "unit_10.php",
        '''<?php
echo "Hello, " . ($_GET["n"] ?? "");
''',
    ),
    (
        "xss-store",
        "client-side",
        "unit_11.php",
        '''<?php
$p = "/tmp/notes.txt";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    file_put_contents($p, ($_POST["b"] ?? "") . "\\n", FILE_APPEND);
}
echo file_get_contents($p);
''',
    ),
    (
        "xss-ref",
        "client-side",
        "unit_12.js",
        '''const express = require("express");
const router = express.Router();

router.get("/g", (req, res) => {
    const n = req.query.n;
    res.send("<h1> Hello :" + n + "</h1>");
});

module.exports = router;
''',
    ),
    (
        "xxe",
        "injection",
        "unit_13.php",
        '''<?php
libxml_disable_entity_loader(false);
$raw = $_GET["x"] ?? "<root><c>none</c></root>";
$doc = new DOMDocument();
$doc->loadXML($raw, LIBXML_NOENT | LIBXML_DTDLOAD);
$s = simplexml_import_dom($doc);
echo $s->c;
''',
    ),
    (
        "redir",
        "web-protocol-auth",
        "unit_14.php",
        '''<?php
header("Location: " . ($_GET["go"] ?? "/"));
die();
''',
    ),
    (
        "redir-3xx",
        "web-protocol-auth",
        "unit_15.js",
        '''const express = require("express");
const router = express.Router();

router.get("/g", function (req, res) {
    const u = encodeURI(req.query.u);
    res.redirect(u);
});

module.exports = router;
''',
    ),
    (
        "ssrf",
        "feature-abuse",
        "unit_16.js",
        '''const express = require("express");
const router = express.Router();
const request = require("request");

router.post("/p", (req, res) => {
    pull(req.body.u, () => {
        res.send("ok");
    });
});

const pull = (u, done) => {
    request({ uri: u, method: "GET", followAllRedirects: true })
        .on("data", () => {})
        .on("end", () => done())
        .on("error", (err) => console.log(err));
};

module.exports = router;
''',
    ),
    (
        "idor",
        "access-control",
        "unit_17.php",
        '''<?php
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
if (strlen($id) > 0) {
    $q = $db->query("select * from notes where id = " . (int)$id);
    while ($row = $q->fetchArray()) {
        echo $row["body"];
    }
} else {
    $q = $db->query("select * from notes where owner = 1");
    while ($row = $q->fetchArray()) {
        echo $row["id"];
    }
}
''',
    ),
    (
        "frame",
        "client-side",
        "unit_18.php",
        '''<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $to = $_POST["to"] ?? "";
    $n = $_POST["n"] ?? "0";
    echo "sent " . $n . " to " . $to;
    exit;
}
?>
<html>
<body>
<form method="post">
<input name="to">
<input name="n" value="100">
<button type="submit">ok</button>
</form>
</body>
</html>
''',
    ),
    (
        "ldap",
        "injection",
        "unit_19.php",
        '''<?php
$dn = $_GET["h"] ?? "";
$who = $_GET["w"] ?? "";
$filter = "(|(sn=$who*)(givenname=$who*))";
$sr = ldap_search($ds, $dn, $filter, array("ou", "sn", "givenname", "mail"));
$info = ldap_get_entries($ds, $sr);
echo $info["count"];
''',
    ),
    (
        "auth",
        "access-control",
        "unit_20.php",
        '''<?php
session_start();
$key = $_SERVER["HTTP_X_STARSHIP_REQUEST_KEY"] ?? "";
$name = $_SERVER["HTTP_X_STARSHIP_USERNAME_KEY"] ?? "";
if ($key !== "") {
    $_SESSION["login"] = "admin";
    $_SESSION["rest"] = $key;
    $_SESSION["who"] = $name;
}
if (($_SESSION["login"] ?? "") === "admin") {
    echo file_get_contents("/var/app/roster.json");
}
''',
    ),
    (
        "reset",
        "web-protocol-auth",
        "unit_21.py",
        '''from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/r")
def r():
    host = request.headers.get("Host", "")
    acct = request.args.get("a", "")
    body = "open http://" + host + "/n/" + acct
    return jsonify({"to": acct, "email_body": body})
''',
    ),
]


def main() -> None:
    TREE.mkdir(parents=True, exist_ok=True)
    for p in TREE.iterdir():
        if p.is_file():
            p.unlink()
    findings = []
    for oid, cls, name, body in UNITS:
        (TREE / name).write_text(body, encoding="utf-8")
        findings.append(
            {
                "id": oid,
                "class": cls,
                "sink_path": name,
                "sink_symbol": "",
                "kinds": [],
                "match": {"path_suffix": name},
            }
        )
    GT.write_text(
        json.dumps(
            {
                "target": "fixtures/profile_eval/tree",
                "description": (
                    "Frozen live hunt-profile recall set. One oracle per listed "
                    "weakness. Matching is path-only so stripped symbols still score."
                ),
                "findings": findings,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(UNITS)} files to {TREE}")


if __name__ == "__main__":
    main()
