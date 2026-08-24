<?php
$base = "/var/www/html/store/";
$kind = $_FILES["f"]["type"] ?? "";
$size = $_FILES["f"]["size"] ?? 0;
$name = $_FILES["f"]["name"] ?? "x";
if (($kind === "image/jpeg" || $kind === "image/png") && $size < 100000) {
    $dest = $base . $name;
    move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
    echo $dest;
} else {
    echo "no";
}
