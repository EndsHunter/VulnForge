const express = require("express");
const router = express.Router();

router.get("/g", (req, res) => {
    const n = req.query.n;
    res.send("<h1> Hello :" + n + "</h1>");
});

module.exports = router;
