<?php
$go = $_GET["go"] ?? "/";
$ok = array("/", "/app/", "https://ok.example/");
$pass = false;
foreach ($ok as $p) {
    if (strpos($go, $p) === 0) {
        $pass = true;
    }
}
if ($pass) {
    header("Location: " . $go);
    die();
}
echo "no";
