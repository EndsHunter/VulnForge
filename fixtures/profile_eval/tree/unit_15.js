const express = require("express");
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
