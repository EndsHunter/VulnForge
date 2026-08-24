<?php
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
