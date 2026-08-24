#!/usr/bin/env python3
"""Write the frozen 21-class hunt-profile eval tree.

Hard set: fake sanitizers, prefix allowlists, alg-from-header JWT, second-order
store, and split source/sink. Names and comments from the public labs are gone.
Sources include SasanLabs/VulnerableApp, snoopysecurity snippets, and
TheDamnVulnerableCodebase, rewritten.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / "fixtures" / "profile_eval" / "tree"
GT = ROOT / "fixtures" / "profile_eval" / "ground_truth.json"

UNITS: list[tuple[str, str, str, str]] = [
    (
        "jwt",
        "web-protocol-auth",
        "unit_01.py",
        '''import json
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
''',
    ),
    (
        "cmd",
        "injection",
        "unit_02.php",
        '''<?php
$d = $_GET["d"] ?? "";
$d = str_replace(array(";", "&", "|"), "", $d);
if (strpos($d, " ") === 0) {
    $d = ltrim($d);
}
system("/usr/bin/host " . $d);
''',
    ),
    (
        "crypto",
        "cryptography",
        "unit_03.py",
        '''import hashlib
from Crypto.Cipher import AES
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "x"
K = b"Sixteen byte key"
IV = b"\\x00" * 16


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
''',
    ),
    (
        "upload",
        "feature-abuse",
        "unit_04.php",
        '''<?php
$base = "/var/www/html/store/";
$kind = $_FILES["f"]["type"] ?? "";
$size = $_FILES["f"]["size"] ?? 0;
$name = $_FILES["f"]["name"] ?? "x";
if (($kind === "image/jpeg" || $kind === "image/png") && $size < 100000) {
    $dest = $base . $name;
    move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
    echo $dest;
} else {
    echo "no";
}
''',
    ),
    (
        "path",
        "injection",
        "unit_05.php",
        '''<?php
$rel = $_POST["p"] ?? "";
$rel = str_replace("../", "", $rel);
if (strpos($rel, "notes") === false) {
    $path = "/var/www/html/" . $rel;
    $h = fopen($path, "rb");
    echo fread($h, 8192);
    fclose($h);
}
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
    name = name.replace(";", "")
    tmpl = "SELECT * FROM items WHERE label LIKE ?"
    q = tmpl.replace("?", "'" + name + "'")
    with eng.connect() as c:
        c.execute(text(q))
    return "ok"
''',
    ),
    (
        "sql-err",
        "injection",
        "unit_07.php",
        '''<?php
$sku = $_GET["sku"] ?? "";
$sku = str_replace("'", "", $sku);
$q = "SELECT * FROM items WHERE sku = '" . $sku . "'";
$r = mysql_query($q);
if (!$r) {
    echo mysql_error();
    exit;
}
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
if (preg_match("/union/i", $cat)) {
    $cat = preg_replace("/union/i", "", $cat);
}
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
$id = str_replace(array(" ", "--"), "", $id);
$n = $db->querySingle("select count(*) from notes where id = " . $id);
if ($n > 0) {
    usleep(200000);
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
$n = htmlspecialchars($_GET["n"] ?? "", ENT_NOQUOTES);
echo '<input value="' . $n . '">';
''',
    ),
    (
        "xss-store",
        "client-side",
        "unit_11.php",
        '''<?php
$p = "/tmp/notes.txt";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $b = strip_tags($_POST["b"] ?? "", "<img><svg>");
    file_put_contents($p, $b . "\\n", FILE_APPEND);
}
$raw = file_get_contents($p);
echo "<script>var n = " . json_encode($raw) . "; document.write(n);</script>";
''',
    ),
    (
        "xss-ref",
        "client-side",
        "unit_12.js",
        '''const express = require("express");
const router = express.Router();

router.get("/g", (req, res) => {
    const n = String(req.query.n || "").replace(/<script/gi, "");
    res.send("<div id=x></div><script>x.innerHTML = decodeURIComponent('" + encodeURIComponent(n) + "')</script>");
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
$raw = file_get_contents("php://input");
if ($raw === "") {
    $raw = $_POST["x"] ?? "<root><c>none</c></root>";
}
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
$go = $_GET["go"] ?? "/";
$ok = array("/", "/app/", "https://ok.example/");
$pass = false;
foreach ($ok as $p) {
    if (strpos($go, $p) === 0) {
        $pass = true;
    }
}
if ($pass) {
    header("Location: " . $go);
    die();
}
echo "no";
''',
    ),
    (
        "redir-3xx",
        "web-protocol-auth",
        "unit_15.js",
        '''const express = require("express");
const router = express.Router();

router.get("/g", function (req, res) {
    let u = String(req.query.u || "/");
    if (u.indexOf("http://evil") !== -1) {
        u = "/";
    }
    const enc = encodeURI(u);
    res.redirect(enc);
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
const { URL } = require("url");

function valid(u) {
    try {
        const o = new URL(u);
        return Boolean(o.protocol && o.host);
    } catch (e) {
        return false;
    }
}

router.post("/p", (req, res) => {
    const u = req.body.u;
    if (!valid(u)) {
        return res.send("no");
    }
    if (String(u).indexOf("localhost") !== -1) {
        return res.send("no");
    }
    request({ uri: u, method: "GET", followAllRedirects: true })
        .on("data", () => {})
        .on("end", () => res.send("ok"))
        .on("error", (err) => res.send(String(err)));
});

module.exports = router;
''',
    ),
    (
        "idor",
        "access-control",
        "unit_17.php",
        '''<?php
session_start();
if (!isset($_SESSION["uid"])) {
    $_SESSION["uid"] = 1;
}
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
if (strlen($id) > 0 && ctype_digit($id)) {
    $q = $db->query("select * from notes where id = " . (int)$id);
    while ($row = $q->fetchArray()) {
        echo $row["body"];
    }
} else {
    $uid = (int)$_SESSION["uid"];
    $q = $db->query("select * from notes where owner = " . $uid);
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
if ($_SERVER["REQUEST_METHOD"] === "GET") {
    header("X-Frame-Options: ALLOWALL");
}
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $to = $_POST["to"] ?? "";
    $n = $_POST["n"] ?? "0";
    echo "sent " . htmlspecialchars($n) . " to " . htmlspecialchars($to);
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
$who = $_GET["w"] ?? "";
$who = str_replace("*", "", $who);
$filter = "(|(uid=" . $who . ")(mail=" . $who . "))";
$sr = ldap_search($ds, "dc=app,dc=tld", $filter, array("ou", "sn", "uid", "mail"));
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
$mac = $_SERVER["HTTP_X_STARSHIP_MAC"] ?? "";
$expect = md5($key);
if ($key !== "" && $mac == $expect) {
    $_SESSION["login"] = "admin";
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
        '''import hashlib
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
''',
    ),
]


def main() -> None:
    TREE.mkdir(parents=True, exist_ok=True)
    keep = {name for _i, _c, name, _b in UNITS}
    for p in TREE.iterdir():
        if p.is_file() and p.name not in keep:
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
                    "Hard live hunt-profile recall set. Fake sanitizers, prefix "
                    "allowlists, alg-from-header JWT, second-order store. Path-only match."
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
