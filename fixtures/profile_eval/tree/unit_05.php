<?php
$rel = $_POST["p"] ?? "";
$rel = str_replace("../", "", $rel);
if (strpos($rel, "notes") === false) {
    $path = "/var/www/html/" . $rel;
    $h = fopen($path, "rb");
    echo fread($h, 8192);
    fclose($h);
}
