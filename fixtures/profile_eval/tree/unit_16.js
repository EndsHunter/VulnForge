const express = require("express");
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
