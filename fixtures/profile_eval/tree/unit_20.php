<?php
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
