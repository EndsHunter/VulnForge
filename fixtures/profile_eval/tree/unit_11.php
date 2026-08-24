<?php
$p = "/tmp/notes.txt";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    file_put_contents($p, ($_POST["b"] ?? "") . "\n", FILE_APPEND);
}
echo file_get_contents($p);
