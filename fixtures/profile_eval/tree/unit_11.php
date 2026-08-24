<?php
$p = "/tmp/notes.txt";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $b = strip_tags($_POST["b"] ?? "", "<img><svg>");
    file_put_contents($p, $b . "\n", FILE_APPEND);
}
$raw = file_get_contents($p);
echo "<script>var n = " . json_encode($raw) . "; document.write(n);</script>";
