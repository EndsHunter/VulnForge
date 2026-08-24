const express = require("express");
const router = express.Router();

router.get("/g", (req, res) => {
    const n = String(req.query.n || "").replace(/<script/gi, "");
    res.send("<div id=x></div><script>x.innerHTML = decodeURIComponent('" + encodeURIComponent(n) + "')</script>");
});

module.exports = router;
