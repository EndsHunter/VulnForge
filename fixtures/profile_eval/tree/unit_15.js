const express = require("express");
const router = express.Router();

router.get("/g", function (req, res) {
    const u = encodeURI(req.query.u);
    res.redirect(u);
});

module.exports = router;
