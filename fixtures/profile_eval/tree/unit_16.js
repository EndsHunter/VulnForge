const express = require("express");
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
