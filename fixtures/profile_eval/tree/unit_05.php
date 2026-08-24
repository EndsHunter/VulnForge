<?php
$root = "/var/www/";
$rel = $_GET["p"] ?? "";
$path = $root . $rel;
$h = fopen($path, "rb");
while (!feof($h)) {
    echo fread($h, 8192);
}
fclose($h);
